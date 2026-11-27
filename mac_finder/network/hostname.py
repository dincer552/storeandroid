"""Best-effort reverse DNS and Windows NetBIOS hostname resolution."""
import platform
import re
import socket
import subprocess


def resolve_hostname(ip, timeout=1.5):
    """Try reverse DNS/mDNS-aware system resolver, then Windows NetBIOS."""
    try:
        socket.setdefaulttimeout(timeout)
        name = socket.gethostbyaddr(ip)[0].rstrip(".")
        if name and name != ip:
            return name
    except (OSError, socket.herror):
        pass
    finally:
        socket.setdefaulttimeout(None)

    if platform.system().lower() == "windows":
        try:
            result = subprocess.run(
                ["nbtstat", "-A", ip], capture_output=True, text=True, timeout=2,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            for line in result.stdout.splitlines():
                match = re.match(r"^\s*([A-Za-z0-9_.-]{1,15})\s+<00>\s+UNIQUE\b", line, re.I)
                if match:
                    return match.group(1)
        except (OSError, subprocess.SubprocessError):
            pass
    return "Bilinmiyor"
