import argparse
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import nmap_scanner2 as scanner_module
from nmap_scanner2 import (
    add_risk,
    build_port_args,
    diff_results,
    format_banner,
    format_ports,
    grab_banner,
    grab_banner_udp,
    load_scan_file,
    main_cli,
    parse_ports,
    positive_float,
    positive_int,
    printable_lines,
    risk_level,
    save_results,
    show_results,
    valid_target,
)


class InputValidationTests(unittest.TestCase):
    def test_valid_targets(self):
        for target in ("192.168.1.1", "192.168.1.0/24", "localhost", "scan.example.com",
                       "scan.example.com.", "2001:db8::1", "2001:db8::/64"):
            with self.subTest(target=target):
                self.assertTrue(valid_target(target))

    def test_invalid_targets(self):
        for target in ("", "-oNoutfile", "bad host", "-bad.example", "foo..bar", "-1",
                       "x" * 254, "a" * 64 + ".example", "a..example", None):
            with self.subTest(target=target):
                self.assertFalse(valid_target(target))

    def test_parse_ports_and_compress_ranges(self):
        ports = parse_ports("22, 80,100-102,102")
        self.assertEqual(ports, [22, 80, 100, 101, 102])
        self.assertEqual(format_ports(ports), "22,80,100-102")

    def test_invalid_ports(self):
        for value in ("", "0", "65536", "80-22", "80,,81", "1-2-3"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_ports(value)

    def test_empty_port_format(self):
        self.assertEqual(format_ports([]), "")

    def test_port_boundaries_duplicates_and_whitespace(self):
        self.assertEqual(parse_ports(" 1,65535,1 "), [1, 65535])
        self.assertEqual(format_ports([1]), "1")
        self.assertEqual(format_ports(list(range(1, 65536))), "1-65535")

    def test_invalid_port_tokens(self):
        for value in ("+80", "-1", "1.5", "abc", "80-", "-80", "80 - 81", "80, ,81"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_ports(value)

    def test_positive_cli_values(self):
        self.assertEqual(positive_int("4"), 4)
        self.assertEqual(positive_float("0.5"), 0.5)
        for converter, value in ((positive_int, "0"), (positive_int, "-2"),
                                 (positive_float, "nan"), (positive_float, "inf"),
                                 (positive_float, "0")):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    converter(value)

    def test_parse_args_defaults_and_options(self):
        ns = scanner_module.parse_args(["-t", "127.0.0.1"])
        self.assertEqual(ns.type, "quick")
        self.assertEqual(ns.threads, 50)
        self.assertEqual(ns.timeout, 3.0)
        ns = scanner_module.parse_args([
            "--target", "localhost", "--type", "udp", "--output", "json",
            "--threads", "2", "--timeout", "0.2", "--banner", "--yes", "-v",
        ])
        self.assertEqual((ns.type, ns.output, ns.threads, ns.timeout), ("udp", "json", 2, 0.2))
        self.assertTrue(ns.banner and ns.yes and ns.verbose)

    def test_parse_args_rejects_invalid_choices_and_worker_values(self):
        base = ["-t", "127.0.0.1"]
        for extra in (("--type", "bad"), ("--output", "xml"), ("--threads", "0"),
                      ("--threads", "-1"), ("--threads", "many"), ("--timeout", "0"),
                      ("--timeout", "nan"), ("--timeout", "inf"), ("--timeout", "x")):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    scanner_module.parse_args(base + list(extra))


class ScanComparisonTests(unittest.TestCase):
    def test_build_custom_port_args_replaces_scan_port_range(self):
        self.assertEqual(build_port_args("-F -T4", [22, 80]), "-T4 -p 22,80")

    def test_diff_detects_opened_closed_and_changed_services(self):
        old = {"host": {"ports": [
            {"port": 22, "proto": "tcp", "service": "ssh", "version": "old"},
            {"port": 80, "proto": "tcp", "service": "http", "version": ""},
        ]}}
        new = {"host": {"ports": [
            {"port": 22, "proto": "tcp", "service": "ssh", "version": "new"},
            {"port": 443, "proto": "tcp", "service": "https", "version": ""},
        ]}}
        diff = diff_results(old, new)["host"]
        self.assertEqual(diff["opened"][0]["port"], 443)
        self.assertEqual(diff["closed"][0]["port"], 80)
        self.assertEqual(diff["changed"][0]["port"], 22)

    def test_diff_for_new_and_gone_hosts_and_empty_inputs(self):
        self.assertEqual(diff_results({}, {}), {})
        new_host = diff_results({}, {"new": {"ports": []}})["new"]
        gone_host = diff_results({"old": {"ports": []}}, {})["old"]
        self.assertEqual(new_host["status"], "new")
        self.assertEqual(gone_host["status"], "gone")

    def test_custom_args_remove_each_builtin_port_selection(self):
        cases = {
            "-F -T4": "-T4 -p 22",
            "-p- -T4": "-T4 -p 22",
            "-sU --top-ports 100 -T4": "-sU -T4 -p 22",
        }
        for args, expected in cases.items():
            with self.subTest(args=args):
                self.assertEqual(build_port_args(args, [22]), expected)


class ScanFileTests(unittest.TestCase):
    def write_json(self, temp_dir, data):
        path = os.path.join(temp_dir, "scan.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f)
        return path

    def test_load_valid_scan_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            data = {"scan": "Quick", "hosts": {"127.0.0.1": {
                "ports": [{"port": 443, "proto": "tcp", "service": "https"}]
            }}}
            self.assertEqual(load_scan_file(self.write_json(temp_dir, data)), data)

    def test_load_scan_file_rejects_invalid_top_level_and_host_data(self):
        bad_documents = ([], {"hosts": []}, {"hosts": {"host": []}},
                         {"hosts": {"host": {"ports": {}}}})
        for data in bad_documents:
            with self.subTest(data=data), tempfile.TemporaryDirectory() as temp_dir:
                with self.assertRaises(ValueError):
                    load_scan_file(self.write_json(temp_dir, data))

    def test_load_scan_file_rejects_invalid_port_records(self):
        invalid_ports = (
            {}, {"port": 0, "proto": "tcp"}, {"port": 65536, "proto": "tcp"},
            {"port": "80", "proto": "tcp"}, {"port": 80, "proto": "icmp"},
            {"port": True, "proto": "tcp"},
        )
        for port in invalid_ports:
            with self.subTest(port=port), tempfile.TemporaryDirectory() as temp_dir:
                data = {"hosts": {"host": {"ports": [port]}}}
                with self.assertRaises(ValueError):
                    load_scan_file(self.write_json(temp_dir, data))

    def test_load_scan_file_reports_invalid_json_and_missing_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "broken.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write("{")
            with self.assertRaises(json.JSONDecodeError):
                load_scan_file(path)
            with self.assertRaises(FileNotFoundError):
                load_scan_file(os.path.join(temp_dir, "missing.json"))


class PresentationAndBannerTests(unittest.TestCase):
    def test_risk_mapping_and_add_risk(self):
        self.assertEqual(risk_level(22), "LOW")
        self.assertEqual(risk_level(445), "HIGH")
        self.assertEqual(risk_level(65000), "UNKNOWN")
        results = {"host": {"ports": [{"port": 445}, {"port": 65000}]}}
        self.assertIs(add_risk(results), results)
        self.assertEqual([p["risk"] for p in results["host"]["ports"]], ["HIGH", "UNKNOWN"])

    def test_printable_banner_removes_control_bytes(self):
        self.assertEqual(printable_lines(b"HTTP/1.0 200 OK\r\n\x1b[31mServer: test\x1b[0m"),
                         ["HTTP/1.0 200 OK", "[31mServer: test", "[0m"])

    def test_banner_formatting_header_binary_empty_and_truncation(self):
        banner = b"HTTP/1.0 200 OK\r\nDate: today\r\nServer: example\r\n\r\n"
        self.assertEqual(format_banner(banner, header_only=True), "HTTP/1.0 200 OK | Server: example")
        self.assertEqual(format_banner(b"\x00\x01"), "<2 bytes binary>")
        self.assertEqual(format_banner(b""), "")
        self.assertEqual(len(format_banner(b"A" * 200)), 150)

    def test_tcp_banner_http_and_socket_error(self):
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        sock.recv.return_value = b"HTTP/1.0 200 OK\r\nServer: test\r\n\r\n"
        with mock.patch.object(scanner_module.socket, "create_connection", return_value=sock) as create:
            result = grab_banner("127.0.0.1", 80)
        self.assertEqual(result, "HTTP/1.0 200 OK | Server: test")
        sock.sendall.assert_called_once()
        self.assertEqual(create.call_args.args[0], ("127.0.0.1", 80))
        with mock.patch.object(scanner_module.socket, "create_connection", side_effect=OSError("refused")):
            self.assertEqual(grab_banner("127.0.0.1", 80), "")

    def test_tcp_banner_probe_for_redis_and_plain_service(self):
        for port, expected_probe in ((6379, scanner_module.TCP_PROBES[6379]), (22, None)):
            sock = mock.MagicMock()
            sock.__enter__.return_value = sock
            sock.recv.return_value = b"SSH-2.0-test"
            with self.subTest(port=port), mock.patch.object(
                scanner_module.socket, "create_connection", return_value=sock
            ):
                self.assertEqual(grab_banner("localhost", port), "SSH-2.0-test")
                if expected_probe:
                    sock.sendall.assert_called_once_with(expected_probe)
                else:
                    sock.sendall.assert_not_called()

    def test_udp_banner_probe_ipv4_ipv6_and_socket_error(self):
        udp_sock = mock.MagicMock()
        udp_sock.__enter__.return_value = udp_sock
        udp_sock.recv.return_value = b"DNS response"
        with mock.patch.object(scanner_module.socket, "socket", return_value=udp_sock) as factory:
            self.assertEqual(grab_banner_udp("127.0.0.1", 53), "DNS response")
            self.assertEqual(factory.call_args.args, (scanner_module.socket.AF_INET, scanner_module.socket.SOCK_DGRAM))
            udp_sock.send.assert_called_with(scanner_module.UDP_PROBES[53])

        udp_sock6 = mock.MagicMock()
        udp_sock6.__enter__.return_value = udp_sock6
        udp_sock6.recv.return_value = b"answer"
        with mock.patch.object(scanner_module.socket, "socket", return_value=udp_sock6) as factory:
            grab_banner_udp("2001:db8::1", 9999)
            self.assertEqual(factory.call_args.args[0], scanner_module.socket.AF_INET6)
            udp_sock6.send.assert_called_with(scanner_module.UDP_DEFAULT_PROBE)

        with mock.patch.object(scanner_module.socket, "socket", side_effect=OSError("timeout")):
            self.assertEqual(grab_banner_udp("127.0.0.1", 53), "")


class NmapResultTests(unittest.TestCase):
    def test_show_results_handles_no_hosts(self):
        scanner = mock.MagicMock()
        scanner.all_hosts.return_value = []
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(show_results(scanner), {})

    def test_show_results_keeps_open_ports_and_os(self):
        info = mock.MagicMock()
        info.hostname.return_value = "example"
        info.state.return_value = "up"
        info.get.return_value = [{"name": "Linux", "accuracy": "98"}]
        info.all_protocols.return_value = ["tcp"]
        port_data = {
            22: {"state": "open", "product": "OpenSSH", "version": "9", "name": "ssh"},
            23: {"state": "closed", "product": "", "version": "", "name": "telnet"},
        }
        info.__getitem__.side_effect = lambda key: ([{"name": "Linux", "accuracy": "98"}]
                                                    if key == "osmatch" else port_data)
        fake_scanner = mock.MagicMock()
        fake_scanner.all_hosts.return_value = ["127.0.0.1"]
        fake_scanner.__getitem__.return_value = info
        with contextlib.redirect_stdout(io.StringIO()):
            results = show_results(fake_scanner)
        self.assertEqual(results["127.0.0.1"]["os"], "Linux")
        self.assertEqual(len(results["127.0.0.1"]["ports"]), 1)
        self.assertEqual(results["127.0.0.1"]["ports"][0]["version"], "OpenSSH 9")

    def test_save_results_writes_valid_json(self):
        previous = os.getcwd()
        with tempfile.TemporaryDirectory() as temp_dir:
            os.chdir(temp_dir)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    save_results({}, "Quick", "127.0.0.1")
                filenames = os.listdir(temp_dir)
                self.assertEqual(len(filenames), 1)
                with open(os.path.join(temp_dir, filenames[0]), encoding="utf-8") as f:
                    saved = json.load(f)
                self.assertEqual(saved["scan"], "Quick")
                self.assertEqual(saved["target"], "127.0.0.1")
                self.assertEqual(saved["hosts"], {})
            finally:
                os.chdir(previous)


class CliFlowTests(unittest.TestCase):
    def test_cli_rejects_invalid_target_without_scanning(self):
        with mock.patch.object(scanner_module, "setup_logging"), mock.patch.object(
            scanner_module, "run_scan_with_progress"
        ) as run_scan:
            self.assertEqual(main_cli(["-t", "bad target", "--yes"]), 1)
        run_scan.assert_not_called()

    def test_cli_cancel_and_nmap_failure(self):
        with mock.patch.object(scanner_module, "setup_logging"), mock.patch(
            "builtins.input", return_value="n"
        ), mock.patch.object(scanner_module, "run_scan_with_progress") as run_scan:
            self.assertEqual(main_cli(["-t", "127.0.0.1"]), 0)
        run_scan.assert_not_called()
        with mock.patch.object(scanner_module, "setup_logging"), mock.patch.object(
            scanner_module, "run_scan_with_progress", side_effect=scanner_module.nmap.PortScannerError("no nmap")
        ):
            self.assertEqual(main_cli(["-t", "127.0.0.1", "--yes"]), 1)

    def test_cli_keyboard_interrupt_returns_shell_interrupt_code(self):
        with mock.patch.object(scanner_module, "setup_logging"), mock.patch.object(
            scanner_module, "run_scan_with_progress", side_effect=KeyboardInterrupt
        ):
            self.assertEqual(main_cli(["-t", "127.0.0.1", "--yes"]), 130)


if __name__ == "__main__":
    unittest.main()
