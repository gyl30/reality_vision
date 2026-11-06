#!/usr/bin/env python3
"""TUN RST 判定的确定性回归；不配置网络。"""

import errno
import socket
import unittest
from unittest.mock import MagicMock, patch

import run_tun_interop as tun


class TunResetTests(unittest.TestCase):
    def test_connect_reset(self):
        with patch.object(tun.socket, "create_connection", side_effect=ConnectionResetError(errno.ECONNRESET, "reset")):
            self.assertEqual(tun.run_reset_check(), 0)

    def test_connect_refused(self):
        with patch.object(tun.socket, "create_connection", side_effect=ConnectionRefusedError(errno.ECONNREFUSED, "refused")):
            self.assertEqual(tun.run_reset_check(), 0)

    def test_receive_reset(self):
        connection = MagicMock()
        connection.__enter__.return_value.recv.side_effect = ConnectionResetError(errno.ECONNRESET, "reset")
        with patch.object(tun.socket, "create_connection", return_value=connection):
            self.assertEqual(tun.run_reset_check(), 0)
        connection.__exit__.assert_called_once()

    def test_connect_unexpected_errors(self):
        for code in (errno.ETIMEDOUT, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM):
            with self.subTest(code=code), patch.object(tun.socket, "create_connection", side_effect=OSError(code, "unexpected")):
                with self.assertRaises(OSError):
                    tun.run_reset_check()

    def test_receive_unexpected_errors(self):
        for error in (socket.timeout("timeout"), OSError(errno.ENETUNREACH, "unreachable"), ConnectionRefusedError(errno.ECONNREFUSED, "refused")):
            connection = MagicMock()
            connection.__enter__.return_value.recv.side_effect = error
            with self.subTest(error=error), patch.object(tun.socket, "create_connection", return_value=connection):
                with self.assertRaises(OSError):
                    tun.run_reset_check()
            connection.__exit__.assert_called_once()

    def test_fin_or_data_is_not_reset(self):
        for data in (b"", b"unexpected"):
            connection = MagicMock()
            connection.__enter__.return_value.recv.return_value = data
            with self.subTest(data=data), patch.object(tun.socket, "create_connection", return_value=connection):
                with self.assertRaises(RuntimeError):
                    tun.run_reset_check()

    def test_namespace_removed_after_device_assertion_fails(self):
        with patch.object(tun, "assert_tun_absent", side_effect=RuntimeError("device remained")), \
             patch.object(tun, "run_checked") as remove, \
             patch.object(tun.subprocess, "check_output", return_value=""):
            with self.assertRaisesRegex(RuntimeError, "device remained"):
                tun.remove_test_namespace("owned-test-namespace")
        remove.assert_called_once_with(["ip", "netns", "delete", "owned-test-namespace"])


if __name__ == "__main__":
    unittest.main()
