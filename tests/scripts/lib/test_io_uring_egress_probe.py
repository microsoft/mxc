import contextlib
import ctypes
import io
from pathlib import Path
import runpy
import socket
import unittest
from unittest import mock


class RawPacketControls(unittest.TestCase):
    def test_ordinary_traffic_is_checked_when_io_uring_is_unavailable(self):
        probe = Path(__file__).with_name("io_uring_egress_probe.py")
        files = {
            "/proc/net/route": "eth0 00000000 0103000A\n",
            "/proc/net/arp": "10.0.3.1 0x1 0x2 02:00:00:00:00:01 * eth0\n",
            "/sys/class/net/eth0/address": "02:00:00:00:00:02\n",
            "/proc/self/status": "Seccomp:\t2\n",
        }
        reply = bytes.fromhex("4500001c0000000040010000cb0071020a000302") + bytes(8)
        for allowed in (True, False):
            with self.subTest(allowed=allowed):
                raw, packet, source = mock.Mock(), mock.Mock(), mock.Mock()
                raw.recv.return_value = reply
                packet.recv.return_value = bytes(14) + reply
                if not allowed:
                    raw.recv.side_effect = TimeoutError
                    packet.recv.side_effect = TimeoutError
                source.getsockname.return_value = ("10.0.3.2", 9)
                libc = mock.Mock()
                libc.syscall.return_value = -1
                output = io.StringIO()
                code = 0
                with (
                    mock.patch.object(ctypes, "CDLL", return_value=libc),
                    mock.patch.object(ctypes, "get_errno", return_value=1),
                    mock.patch.object(socket, "create_connection"),
                    mock.patch.object(socket, "socket", side_effect=[raw, packet, source]),
                    mock.patch("builtins.open", side_effect=lambda path: io.StringIO(files[path])),
                    mock.patch("sys.argv", [str(probe), "203.0.113.2"]),
                    contextlib.redirect_stdout(output),
                ):
                    try:
                        runpy.run_path(str(probe), run_name="__main__")
                    except SystemExit as error:
                        code = error.code
                self.assertEqual(code, 0, output.getvalue())
                self.assertIn(
                    "MXC_NET_ALLOWED" if allowed else "MXC_NET_BLOCKED",
                    output.getvalue(),
                )
                self.assertIn("MXC_IO_URING_SETUP_FAILED errno=1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
