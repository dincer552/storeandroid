"""Credential-free reachability checks for Meraki local status hostnames."""
import socket
import time
import urllib.parse

LOCAL_STATUS_URLS = (
    "http://switch.meraki.com",
    "http://setup.meraki.com",
    "http://my.meraki.com",
)


def probe_local_status_page(url="http://switch.meraki.com", timeout=3):
    parsed = urllib.parse.urlparse(url)
    allowed = {urllib.parse.urlparse(item).hostname for item in LOCAL_STATUS_URLS}
    if parsed.scheme != "http" or parsed.hostname not in allowed:
        raise ValueError("Yalnızca bilinen Meraki local status adresleri kontrol edilebilir.")
    result = {
        "url": url, "hostname": parsed.hostname, "addresses": [], "reachable": False,
        "http_status": None, "checked_at": time.time(), "error": "",
    }
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 80, type=socket.SOCK_STREAM)
    except OSError as exc:
        result["error"] = f"DNS çözümlemesi başarısız: {exc}"
        return result
    result["addresses"] = sorted({item[4][0] for item in addresses})
    for address in result["addresses"]:
        try:
            with socket.create_connection((address, parsed.port or 80), timeout=timeout) as connection:
                connection.settimeout(timeout)
                connection.sendall((
                    f"GET / HTTP/1.0\r\nHost: {parsed.netloc}\r\n"
                    "User-Agent: MACFinderPro/2.0\r\nConnection: close\r\n\r\n"
                ).encode("ascii"))
                response = connection.recv(256)
                result["reachable"] = True
                if response:
                    parts = response.split(b"\r\n", 1)[0].decode("latin-1", errors="replace").split()
                    if len(parts) >= 2 and parts[0].startswith("HTTP/"):
                        try:
                            result["http_status"] = int(parts[1])
                        except ValueError:
                            pass
                return result
        except OSError as exc:
            result["error"] = f"Yerel bağlantı başarısız ({address}): {exc}"
    return result
