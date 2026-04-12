import socket
import subprocess
from urllib.parse import urlparse


class PortScanner:
    DEFAULT_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 8080]

    def __init__(self, target, mode="fast", timeout=30, verbose=False):
        self.target = target
        self.mode = mode
        self.timeout = timeout
        self.verbose = verbose

    def extract_host(self):
        parsed = urlparse(self.target)
        host = parsed.netloc if parsed.netloc else parsed.path
        return host.split(":")[0].strip()

    def socket_scan(self, host):
        results = {}
        if self.verbose:
            print("[*] Running socket fallback scan...")

        for port in self.DEFAULT_PORTS:
            try:
                with socket.socket() as sock:
                    sock.settimeout(1)
                    if sock.connect_ex((host, port)) == 0:
                        results[port] = {
                            "state": "open",
                            "service": "unknown",
                            "method": "socket",
                        }
            except OSError:
                continue
        return results

    def build_nmap_command(self, host):
        if self.mode == "fast":
            return ["nmap", "-T4", "-F", host]
        if self.mode == "normal":
            return ["nmap", "-T4", "-sV", "-p", "1-2000", host]
        if self.mode == "deep":
            return ["nmap", "-T4", "-A", "-p-", host]
        return ["nmap", "-T4", "-F", host]

    def parse_nmap_output(self, output):
        results = {}
        for line in output.splitlines():
            if "/tcp" not in line or "open" not in line:
                continue

            parts = line.split()
            try:
                port = int(parts[0].split("/")[0])
            except (IndexError, ValueError):
                continue

            service = parts[2] if len(parts) > 2 else "unknown"
            results[port] = {
                "state": "open",
                "service": service,
                "method": "nmap",
            }
        return results

    def scan(self):
        host = self.extract_host()
        if not host:
            print("[!] Invalid target")
            return {}

        try:
            ip = socket.gethostbyname(host)
        except OSError as exc:
            print(f"[!] DNS resolution failed: {exc}")
            return {}

        if self.verbose:
            print(f"[+] Scanning {host} ({ip}) with Nmap")

        try:
            cmd = self.build_nmap_command(ip)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            if result.returncode != 0:
                if self.verbose:
                    print("[!] Nmap failed -> using socket fallback")
                return self.socket_scan(ip)

            parsed = self.parse_nmap_output(result.stdout)
            if parsed:
                return parsed

            if self.verbose:
                print("[!] No ports found via Nmap -> using socket fallback")
            return self.socket_scan(ip)
        except FileNotFoundError:
            if self.verbose:
                print("[!] Nmap is not installed -> using socket fallback")
            return self.socket_scan(ip)
        except subprocess.TimeoutExpired:
            if self.verbose:
                print("[!] Nmap timeout -> using socket fallback")
            return self.socket_scan(ip)
        except Exception as exc:
            if self.verbose:
                print(f"[!] Error: {exc}")
            return self.socket_scan(ip)
