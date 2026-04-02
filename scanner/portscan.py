import nmap
import socket
from urllib.parse import urlparse
import threading


class PortScanner:
    """Advanced port scanner with Nmap + socket fallback and timeout support."""

    DEFAULT_SOCKET_PORTS = [20, 21, 22, 23, 25, 80, 139, 443, 445, 3306, 3389, 8080]

    def __init__(self, target, mode="normal", nmap_timeout=30, verbose=False):
        """
        target      : URL or hostname
        mode        : "fast" / "normal" / "deep"
        nmap_timeout: Maximum seconds to wait for Nmap scan
        verbose     : Print debug output if True
        """
        self.target = target
        self.mode = mode
        self.nmap_timeout = nmap_timeout
        self.verbose = verbose
        self.open_ports = {}

    # ================= HOST EXTRACT =================
    def extract_host(self):
        parsed = urlparse(self.target)
        host = parsed.netloc if parsed.netloc else parsed.path
        host = host.split(":")[0]
        return host.strip()

    # ================= SOCKET FALLBACK =================
    def basic_socket_scan(self, host, ports=None):
        if ports is None:
            ports = self.DEFAULT_SOCKET_PORTS

        open_ports = {}

        for port in ports:
            try:
                s = socket.socket()
                s.settimeout(1)

                if s.connect_ex((host, port)) == 0:
                    open_ports[port] = {
                        "name": "unknown",
                        "state": "open",
                        "product": "socket-detected",
                        "version": ""
                    }

                s.close()

            except Exception as e:
                if self.verbose:
                    print(f"[!] Socket error on port {port}: {e}")
                continue

        return open_ports

    # ================= GET NMAP ARGUMENTS =================
    def _get_nmap_args(self):
        if self.mode == "fast":
            return "-T4 -F -sS"
        elif self.mode == "normal":
            return "-T4 -sS -sV -p 1-2000 --script=default"
        elif self.mode == "deep":
            return "-T4 -A -p-"
        else:
            return "-T4 -F -sS"

    # ================= MAIN SCAN =================
    def scan(self):
        host = self.extract_host()

        if not host:
            if self.verbose:
                print("[!] Invalid target")
            return {}

        try:
            ip = socket.gethostbyname(host)
        except Exception as e:
            if self.verbose:
                print(f"[!] DNS resolution failed: {e}")
            return {}

        if self.verbose:
            print(f"[+] Scanning {host} ({ip}) using mode: {self.mode}")

        # ---------------- NMAP SCAN ----------------
        def nmap_scan():
            try:
                nm = nmap.PortScanner()
                nm.scan(ip, arguments=self._get_nmap_args())

                for proto in nm[ip].all_protocols():
                    for port in nm[ip][proto]:
                        data = nm[ip][proto][port]

                        if data["state"] == "open":
                            self.open_ports[port] = {
                                "name": data.get("name", "unknown"),
                                "state": data["state"],
                                "product": data.get("product", ""),
                                "version": data.get("version", ""),
                                "extra": data.get("extrainfo", "")
                            }

            except Exception as e:
                if self.verbose:
                    print(f"[!] Nmap error: {e}")

        t = threading.Thread(target=nmap_scan)
        t.start()
        t.join(timeout=self.nmap_timeout)

        # ---------------- TIMEOUT HANDLING ----------------
        if t.is_alive():
            if self.verbose:
                print("[!] Nmap timeout → switching to socket scan")
            return self.basic_socket_scan(ip)

        # ---------------- FALLBACK ----------------
        if not self.open_ports:
            if self.verbose:
                print("[!] No results from Nmap → using socket scan")
            return self.basic_socket_scan(ip)

        if self.verbose:
            print(f"[✓] Found {len(self.open_ports)} open ports")

        return self.open_ports