import ctypes, mmap, socket, struct, sys
PEER = sys.argv[1]
libc = ctypes.CDLL(None, use_errno=True)

# ICMP echo request with its checksum and zero identifier and sequence.
ECHO_REQUEST = bytes.fromhex("0800f7ff00000000")

ping = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
ping.settimeout(3)
ping.sendto(ECHO_REQUEST, (PEER, 0))
try:
    ping.recv(64)
except OSError:
    raise SystemExit("MXC_PEER_UNREACHABLE")

params = ctypes.create_string_buffer(120)
ring = libc.syscall(425, 1, params)
if ring < 0:
    raise SystemExit("MXC_IO_URING_SETUP_FAILED errno=%d" % ctypes.get_errno())
_, sq_tail, _, _, _, _, sq_array = struct.unpack_from("7I", params, 40)
sq = mmap.mmap(ring, sq_array + 4, offset=0)
sqes = mmap.mmap(ring, 64, offset=0x10000000)
cqes = struct.unpack_from("I", params, 100)[0]
cq = mmap.mmap(ring, cqes + 16, offset=0x8000000)

# IORING_OP_SOCKET takes the family in fd, the type in off, and the protocol in len.
sqes[0:64] = struct.pack("BBHiQQII", 45, 0, 0, socket.AF_INET, socket.SOCK_RAW, 0, socket.IPPROTO_ICMP, 0) + bytes(32)
struct.pack_into("I", sq, sq_array, 0)
struct.pack_into("I", sq, sq_tail, 1)
if libc.syscall(426, ring, 1, 1, 1, None, 0) < 0:
    raise SystemExit("MXC_IO_URING_ENTER_FAILED errno=%d" % ctypes.get_errno())

# The completion contains the new socket descriptor or a negative error.
fd = struct.unpack_from("i", cq, cqes + 8)[0]
if fd < 0:
    print("MXC_NET_BLOCKED")
    raise SystemExit(0)

raw = socket.socket(fileno=fd)
raw.settimeout(3)
raw.sendto(ECHO_REQUEST, (PEER, 0))
try:
    while True:
        reply, address = raw.recvfrom(2048)
        if address[0] == PEER and reply[(reply[0] & 0x0F) * 4] == 0:
            print("MXC_NET_ALLOWED")
            break
except socket.timeout:
    print("MXC_NET_BLOCKED")
