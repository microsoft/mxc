import errno, socket

for name, family, kind, protocol in (
    ("raw", socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP),
    ("packet", socket.AF_PACKET, socket.SOCK_RAW, 0),
):
    try:
        socket.socket(family, kind, protocol).close()
        print(name, "OPENED")
    except OSError as error:
        print(name, errno.errorcode[error.errno])
