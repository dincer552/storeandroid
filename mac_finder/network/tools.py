"""Network diagnostics and deliberately scoped TCP checks."""
import platform
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from .adapter import get_active_adapters

COMMON_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS", 80:"HTTP",
    110:"POP3", 123:"NTP", 135:"RPC", 139:"NetBIOS", 143:"IMAP",
    443:"HTTPS", 445:"SMB", 502:"Modbus TCP", 1883:"MQTT",
    3389:"RDP", 4840:"OPC UA", 8080:"HTTP-alt", 8443:"HTTPS-alt"
}


def scan_tcp_ports(host, ports, timeout=0.55, workers=32):
    """Check explicitly selected TCP ports on one host; no service exploitation."""
    try:
        socket.gethostbyname(host)
    except OSError as exc:
        raise ValueError(f"Hedef çözümlenemedi: {exc}")
    valid = sorted({int(port) for port in ports if 1 <= int(port) <= 65535})
    if not valid or len(valid) > 512:
        raise ValueError("1-512 adet geçerli TCP portu seçin.")

    def check(port):
        started = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            is_open = sock.connect_ex((host, port)) == 0
            return {
                "port": port, "service": COMMON_PORTS.get(port, "Unknown"),
                "state": "Açık" if is_open else "Kapalı/Filtreli",
                "latency_ms": round((time.perf_counter() - started) * 1000, 1)
            }
        finally:
            sock.close()

    with ThreadPoolExecutor(max_workers=min(workers, len(valid))) as pool:
        return sorted(pool.map(check, valid), key=lambda result: result["port"])


def run_diagnostics():
    """Report local adapter configuration and a basic gateway reachability test."""
    adapters = get_active_adapters()
    if not adapters:
        return [{"test":"Ağ adaptörü", "result":"Aktif IPv4 adaptörü bulunamadı", "ok":False}]
    adapter = adapters[0]
    tests = [
        {"test":"IPv4", "result":adapter["ip"], "ok":True},
        {"test":"Subnet", "result":f"/{adapter['prefixlen']}", "ok":True},
        {"test":"Gateway", "result":adapter.get("gateway", "Bilinmiyor"),
         "ok":adapter.get("gateway") not in (None, "Bilinmiyor")},
        {"test":"Ethernet link", "result":f"{adapter.get('speed_mbps', 0)} Mbps / Duplex {adapter.get('duplex', 'Bilinmiyor')}", "ok":True}
    ]
    gateway = adapter.get("gateway")
    if gateway and gateway != "Bilinmiyor":
        system = platform.system().lower()
        command = (["ping", "-n", "1", "-w", "1200", gateway] if system == "windows"
                   else ["ping", "-c", "1", "-W", "1", gateway])
        try:
            started = time.perf_counter()
            result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=3, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if system == "windows" else 0)
            elapsed = (time.perf_counter() - started) * 1000
            ok = result.returncode == 0
            tests.append({"test":"Gateway ICMP",
                "result":f"Yanıt alındı ({elapsed:.0f} ms)" if ok else "Yanıt alınamadı / ICMP engelli",
                "ok":ok})
        except (OSError, subprocess.SubprocessError) as exc:
            tests.append({"test":"Gateway ICMP", "result":f"Kontrol edilemedi: {exc}", "ok":False})
    return tests
