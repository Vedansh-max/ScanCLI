import subprocess
import socket
from urllib.parse import urlparse


class PortScanner:
    def __init__(self, target, mode="fast", timeout=30, verbose=False):
        self.target = target
        self.mode = mode
        self.timeout = timeout
        self.verbose = verbose

    # ================= HOST EXTRACT =================
    def extract_host(self):
        parsed = urlparse(self.target)
        host = parsed.netloc if parsed.netloc else parsed.path
        return host.split(":")[0].strip()

    # ================= SOCKET FALLBACK =================
    def socket_scan(self, host):
        ports = [20, 21, 22, 23, 25, 80, 139, 443, 445, 3306, 3389, 8080]
        results = {}

        if self.verbose:
            print("[*] Running socket fallback scan...")

        for port in ports:
            try:
                s = socket.socket()
                s.settimeout(1)

                if s.connect_ex((host, port)) == 0:
                    results[port] = {
                        "state": "open",
                        "service": "unknown",
                        "method": "socket"
                    }

                s.close()

            except Exception:
                continue

        return results

    # ================= BUILD NMAP COMMAND =================
    def build_nmap_command(self, host):
        if self.mode == "fast":
            return ["nmap", "-T4", "-F", host]

        elif self.mode == "normal":
            return ["nmap", "-T4", "-sV", "-p", "1-2000", host]

        elif self.mode == "deep":
            return ["nmap", "-T4", "-A", "-p-", host]

        else:
            return ["nmap", "-T4", "-F", host]

    # ================= PARSE OUTPUT =================
    def parse_nmap_output(self, output):
        results = {}

        for line in output.split("\n"):
            if "/tcp" in line and "open" in line:
                parts = line.split()

                try:
                    port = int(parts[0].split("/")[0])
                    service = parts[2] if len(parts) > 2 else "unknown"

                    results[port] = {
                        "state": "open",
                        "service": service,
                        "method": "nmap"
                    }

                except Exception:
                    continue

        return results

    # ================= MAIN SCAN =================
    def scan(self):
        host = self.extract_host()

        if not host:
            print("[!] Invalid target")
            return {}

        try:
            ip = socket.gethostbyname(host)
        except Exception as e:
            print(f"[!] DNS resolution failed: {e}")
            return {}

        if self.verbose:
            print(f"[+] Scanning {host} ({ip}) with Nmap")

        try:
            cmd = self.build_nmap_command(ip)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            if result.returncode != 0:
                if self.verbose:
                    print("[!] Nmap failed → using socket fallback")
                return self.socket_scan(ip)

            parsed = self.parse_nmap_output(result.stdout)

            if not parsed:
                if self.verbose:
                    print("[!] No ports found → using fallback")
                return self.socket_scan(ip)

            return parsed

        except subprocess.TimeoutExpired:
            if self.verbose:
                print("[!] Nmap timeout → using fallback")
            return self.socket_scan(ip)

        except Exception as e:
            if self.verbose:
                print(f"[!] Error: {e}")
            return self.socket_scan(ip)
