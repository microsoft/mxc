import ctypes, errno, mmap, socket, struct

IO_URING_SETUP = 425
IO_URING_ENTER = 426
IORING_OP_SOCKET = 45
IORING_ENTER_GETEVENTS = 1
IORING_OFF_CQ_RING = 0x8000000
IORING_OFF_SQES = 0x10000000

libc = ctypes.CDLL(None, use_errno=True)
params = ctypes.create_string_buffer(120)
ring = libc.syscall(IO_URING_SETUP, 4, params)
if ring < 0:
    raise SystemExit("io_uring_setup " + errno.errorcode[ctypes.get_errno()])

# Read the ring sizes and the ring offsets out of struct io_uring_params.
sq_entries, cq_entries = struct.unpack_from("II", params, 0)
sq_head, sq_tail, sq_mask, _, _, _, sq_array = struct.unpack_from("7I", params, 40)
cq_head, _, cq_mask, _, _, cqes = struct.unpack_from("6I", params, 80)

sq = mmap.mmap(ring, sq_array + sq_entries * 4, offset=0)
cq = mmap.mmap(ring, cqes + cq_entries * 16, offset=IORING_OFF_CQ_RING)
sqes = mmap.mmap(ring, sq_entries * 64, offset=IORING_OFF_SQES)

for name, family, kind, protocol in (
    ("raw", socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP),
    ("packet", socket.AF_PACKET, socket.SOCK_RAW, 0),
):
    # IORING_OP_SOCKET takes the family in fd, the type in off, and the protocol in len.
    sqes[0:64] = struct.pack("BBHiQQII", IORING_OP_SOCKET, 0, 0, family, kind, 0, protocol, 0) + bytes(32)

    tail = struct.unpack_from("I", sq, sq_tail)[0]
    struct.pack_into("I", sq, sq_array + (tail & sq_mask) * 4, 0)
    struct.pack_into("I", sq, sq_tail, tail + 1)
    libc.syscall(IO_URING_ENTER, ring, 1, 1, IORING_ENTER_GETEVENTS, None, 0)

    # The completion result sits 8 bytes in, and holds the new descriptor or a negated errno.
    head = struct.unpack_from("I", cq, cq_head)[0]
    result = struct.unpack_from("i", cq, cqes + (head & cq_mask) * 16 + 8)[0]
    struct.pack_into("I", cq, cq_head, head + 1)

    print(name, "OPENED" if result >= 0 else errno.errorcode[-result])
