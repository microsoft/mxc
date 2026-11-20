import ctypes, errno, json, mmap, os, socket, struct, subprocess, sys, time
PEER = sys.argv[1]
libc = ctypes.CDLL(None, use_errno=True)

def checksum(data):
    word_sum = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    word_sum = (word_sum & 0xFFFF) + (word_sum >> 16)
    return ~((word_sum & 0xFFFF) + (word_sum >> 16)) & 0xFFFF

# ICMP echo request with its checksum and zero identifier and sequence.
ECHO_REQUEST = bytes.fromhex("0800f7ff00000000")

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP) as ping:
    ping.settimeout(3)
    ping.sendto(ECHO_REQUEST, (PEER, 0))
    try:
        ping.recv(64)
    except OSError:
        raise SystemExit("MXC_PEER_UNREACHABLE")

received_reply = False
for family, protocol in (
    (socket.AF_INET, socket.IPPROTO_ICMP),
    (socket.AF_PACKET, socket.htons(0x0800)),
):
    params = ctypes.create_string_buffer(120)
    ring = libc.syscall(425, 1, params)
    if ring < 0:
        raise SystemExit("MXC_IO_URING_SETUP_FAILED errno=%d" % ctypes.get_errno())
    try:
        _, sq_tail, _, _, _, _, sq_array = struct.unpack_from("7I", params, 40)
        cqes = struct.unpack_from("I", params, 100)[0]
        with mmap.mmap(ring, sq_array + 4, offset=0) as sq, \
             mmap.mmap(ring, 64, offset=0x10000000) as sqes, \
             mmap.mmap(ring, cqes + 16, offset=0x8000000) as cq:

            # IORING_OP_SOCKET takes the family in fd, the type in off, and the protocol in len.
            sqes[0:64] = struct.pack("BBHiQQII", 45, 0, 0, family, socket.SOCK_RAW, 0, protocol, 0) + bytes(32)
            struct.pack_into("I", sq, sq_array, 0)
            struct.pack_into("I", sq, sq_tail, 1)
            if libc.syscall(426, ring, 1, 1, 1, None, 0) < 0:
                raise SystemExit("MXC_IO_URING_ENTER_FAILED errno=%d" % ctypes.get_errno())

            # The completion contains the new socket descriptor or a negative error.
            fd = struct.unpack_from("i", cq, cqes + 8)[0]
        if fd in (-errno.EPERM, -errno.EACCES):
            print("socket family=%d refused errno=%d" % (family, -fd))
            continue
        if fd < 0:
            raise SystemExit("MXC_IO_URING_SOCKET_FAILED family=%d errno=%d" % (family, -fd))

        with socket.socket(fileno=fd) as raw:

            # ICMP echo request with a per-family sequence number.
            request = bytearray(struct.pack("!BBHHH", 8, 0, 0, 0, family))
            struct.pack_into("!H", request, 2, checksum(request))
            ip_start = 0
            if family == socket.AF_PACKET:
                route = json.loads(subprocess.check_output(["ip", "-j", "route", "get", PEER]))[0]
                interface = route["dev"]
                neighbor = next(
                    row.split() for row in open("/proc/net/arp")
                    if row.split()[0] == route["gateway"] and row.split()[-1] == interface
                )
                gateway_mac = bytes.fromhex(neighbor[3].replace(":", ""))
                if gateway_mac == bytes(6):
                    raise SystemExit("MXC_PEER_GATEWAY_MAC_MISSING")
                own_mac = bytes.fromhex(open("/sys/class/net/%s/address" % interface).read().strip().replace(":", ""))

                # IPv4 header for the echo request.
                ip = bytearray(struct.pack(
                    "!BBHHHBBH4s4s", 0x45, 0, 20 + len(request), 0, 0, 64, 1, 0,
                    socket.inet_aton(route["prefsrc"]), socket.inet_aton(PEER),
                ))
                struct.pack_into("!H", ip, 10, checksum(ip))
                raw.sendto(gateway_mac + own_mac + bytes.fromhex("0800") + ip + request, (interface, 0x0800))
                ip_start = 14
            else:
                raw.sendto(request, (PEER, 0))

            deadline = time.monotonic() + 3
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    raw.settimeout(remaining)
                    reply = raw.recv(2048)
                    icmp = ip_start + (reply[ip_start] & 0x0F) * 4
                    if (
                        socket.inet_ntoa(reply[ip_start + 12:ip_start + 16]) == PEER
                        and reply[ip_start + 9] == socket.IPPROTO_ICMP
                        and reply[icmp] == 0
                        and reply[icmp + 4:icmp + 8] == request[4:]
                    ):
                        received_reply = True
                        print("socket family=%d echo reply received" % family)
                        print("MXC_NET_ALLOWED")
                        break
            except socket.timeout:
                pass
    finally:
        os.close(ring)

if not received_reply:
    print("MXC_NET_BLOCKED")
