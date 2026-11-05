import ctypes, mmap, os, socket, struct, sys
PEER = sys.argv[1]
libc = ctypes.CDLL(None, use_errno=True)

def checksum(data):
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    return ~(total + (total >> 16)) & 0xFFFF

def echo(ident):
    return struct.pack("!BBHHH", 8, 0, checksum(struct.pack("!BBHHH", 8, 0, 0, ident, 1)), ident, 1)

def replied(sock, ip_start):
    sock.settimeout(3)
    try:
        while True:
            data = sock.recv(2048)
            icmp = ip_start + (data[ip_start] & 0x0F) * 4
            if socket.inet_ntoa(data[ip_start + 12:ip_start + 16]) == PEER and data[icmp] == 0:
                return True
    except OSError:
        return False

def io_uring_socket(family, kind, protocol):
    params = ctypes.create_string_buffer(120)
    ring = libc.syscall(425, 1, params)
    if ring < 0:
        error = ctypes.get_errno()
        print(next((line.strip() for line in open("/proc/self/status") if line.startswith("Seccomp:")), "Seccomp: unknown"), flush=True)
        raise SystemExit("MXC_IO_URING_SETUP_FAILED errno=%d" % error)
    _, sq_tail, _, _, _, _, sq_array = struct.unpack_from("7I", params, 40)
    sq = mmap.mmap(ring, sq_array + 4, offset=0)
    sqes = mmap.mmap(ring, 64, offset=0x10000000)
    # IORING_OP_SOCKET takes the family in fd, the type in off, and the protocol in len.
    sqes[0:64] = struct.pack("BBHiQQII", 45, 0, 0, family, kind, 0, protocol, 0) + bytes(32)
    struct.pack_into("I", sq, sq_array, 0)
    struct.pack_into("I", sq, sq_tail, 1)
    # The kernel installs the new socket at the lowest free descriptor.
    fd = os.open("/dev/null", os.O_RDONLY)
    os.close(fd)
    if libc.syscall(426, ring, 1, 1, 1, None, 0) < 0:
        raise SystemExit("MXC_IO_URING_ENTER_FAILED errno=%d" % ctypes.get_errno())
    try:
        return socket.socket(fileno=fd)
    except OSError:
        return None

# A socket ping proves the peer answers and fills the neighbor entry the packet frame needs.
ping = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
ping.settimeout(3)
ping.sendto(echo(1), (PEER, 0))
try:
    ping.recv(64)
except OSError:
    raise SystemExit("MXC_PEER_UNREACHABLE")

escaped = False

raw = io_uring_socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
if raw:
    raw.sendto(echo(2), (PEER, 0))
    escaped |= replied(raw, 0)

packet = io_uring_socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
if packet:
    route = next(line.split() for line in open("/proc/net/route") if line.split()[1] == "00000000")
    gateway = socket.inet_ntoa(struct.pack("<I", int(route[2], 16)))
    gateway_mac = next(line.split()[3] for line in open("/proc/net/arp") if line.split()[0] == gateway)
    own_mac = open("/sys/class/net/" + route[0] + "/address").read().strip()
    source = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    source.connect((PEER, 9))
    payload = echo(3)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, 1, 0, socket.inet_aton(source.getsockname()[0]), socket.inet_aton(PEER))
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    ethernet = bytes.fromhex(gateway_mac.replace(":", "") + own_mac.replace(":", "") + "0800")
    packet.sendto(ethernet + ip + payload, (route[0], 0x0800))
    escaped |= replied(packet, 14)

print("MXC_NET_ALLOWED" if escaped else "MXC_NET_BLOCKED")
