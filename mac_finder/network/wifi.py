"""Windows Native Wi-Fi API wrapper with netsh fallback.

Implements a read-only Wi-Fi scanner and profiler using ctypes bindings to
``wlanapi.dll``.  All results are normalised to plain Python dicts so that
they can be consumed by the UI or persisted to SQLite.

Security scope: strictly read-only discovery.
  * No deauthentication / packet injection.
  * No handshake capture.
  * No credential extraction ("netsh wlan show profile key=clear" is never used).
"""
import ctypes
import platform
import re
import struct
import subprocess
from ctypes import wintypes
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------- constants
DOT11_SSID_MAX_LENGTH = 32
DOT11_BSSID_LIST_SIZE = 32
WLAN_MAX_NAME_LENGTH = 256
DOT11_MAC_ADDRESS_SIZE = 6

WLAN_CONNECTION_MODE_PROFILE = 0
DOT11_PHY_TYPE_UNKNOWN = 0
DOT11_PHY_TYPE_FHSS = 1
DOT11_PHY_TYPE_DSSS = 2
DOT11_PHY_TYPE_IRBASEBAND = 3
DOT11_PHY_TYPE_OFDM = 4
DOT11_PHY_TYPE_HRDSSS = 5
DOT11_PHY_TYPE_ERP = 6
DOT11_PHY_TYPE_HT = 7
DOT11_PHY_TYPE_VHT = 8
DOT11_PHY_TYPE_HE = 9  # Wi-Fi 6E

PHY_TYPE_NAMES = {
    DOT11_PHY_TYPE_UNKNOWN: "Unknown",
    DOT11_PHY_TYPE_FHSS: "FHSS",
    DOT11_PHY_TYPE_DSSS: "DSSS",
    DOT11_PHY_TYPE_IRBASEBAND: "IR",
    DOT11_PHY_TYPE_OFDM: "OFDM",
    DOT11_PHY_TYPE_HRDSSS: "HR/DSSS",
    DOT11_PHY_TYPE_ERP: "ERP",
    DOT11_PHY_TYPE_HT: "HT (Wi-Fi 4)",
    DOT11_PHY_TYPE_VHT: "VHT (Wi-Fi 5)",
    DOT11_PHY_TYPE_HE: "HE (Wi-Fi 6)",
}

DOT11_AUTH_ALGO_OPEN = 0
DOT11_AUTH_ALGO_SHARED = 1
DOT11_AUTH_ALGO_WPAPSK = 2
DOT11_AUTH_ALGO_WPA = 3
DOT11_AUTH_ALGO_WPA2 = 4
DOT11_AUTH_ALGO_WPA3 = 5
DOT11_AUTH_ALGO_RSNA = 6

DOT11_BSS_TYPE_INFRASTRUCTURE = 1

DOT11_PHY_TYPE_HE_INT = DOT11_PHY_TYPE_HE

# ---------------------------------------------------------------- structures
class DOT11_SSID(ctypes.Structure):
    _fields_ = [("uSSIDLength", ctypes.c_uint32),
                ("ucSSID", ctypes.c_ubyte * DOT11_SSID_MAX_LENGTH)]


class WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [("InterfaceIndex", ctypes.c_uint32),
                ("InterfaceGuid", ctypes.c_ubyte * 16),
                ("strInterfaceDescription", ctypes.c_wchar * WLAN_MAX_NAME_LENGTH),
                ("isState", ctypes.c_int)]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", ctypes.c_uint32),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]


class WLAN_PROFILE_INFO(ctypes.Structure):
    _fields_ = [("strProfileName", ctypes.c_wchar * WLAN_MAX_NAME_LENGTH),
                ("dwFlags", ctypes.c_uint32)]


class WLAN_PROFILE_INFO_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", ctypes.c_uint32),
                ("dwIndex", ctypes.c_uint32),
                ("ProfileInfo", WLAN_PROFILE_INFO * 1)]


class WLAN_AVAILABLE_NETWORK(ctypes.Structure):
    _fields_ = [("strProfileName", ctypes.c_wchar * WLAN_MAX_NAME_LENGTH),
                ("dot11Ssid", DOT11_SSID),
                ("dot11BssType", ctypes.c_int),
                ("uNumberOfBssids", ctypes.c_uint32),
                ("bNetworkConnectable", ctypes.c_int),
                ("wlanNotConnectableReason", ctypes.c_uint32),
                ("uNumberOfPhyTypes", ctypes.c_uint32),
                ("dot11PhyTypes", ctypes.c_uint32 * 8),
                ("bMorePhyTypes", ctypes.c_int),
                ("wlanSignalQuality", ctypes.c_uint32),
                ("bSecurityEnabled", ctypes.c_int),
                ("dot11DefaultAuthAlgorithm", ctypes.c_int),
                ("dot11DefaultCipherAlgorithm", ctypes.c_int)]


class WLAN_AVAILABLE_NETWORK_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", ctypes.c_uint32),
                ("dwIndex", ctypes.c_uint32),
                ("Network", WLAN_AVAILABLE_NETWORK * 1)]


class DOT11_BSSID(ctypes.Structure):
    _fields_ = [("dot11Bssid", ctypes.c_ubyte * DOT11_MAC_ADDRESS_SIZE)]


class WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [("dot11Ssid", DOT11_SSID),
                ("uPhyId", ctypes.c_uint32),
                ("dot11Bssid", DOT11_MAC_ADDRESS_SIZE * ctypes.c_ubyte),
                ("dot11BssType", ctypes.c_int),
                ("dot11BssPhyType", ctypes.c_uint32),
                ("lRssi", ctypes.c_int),
                ("uLinkQuality", ctypes.c_uint32),
                ("bInRegDomain", ctypes.c_int),
                ("usBeaconPeriod", ctypes.c_uint16),
                ("ullTimestamp", ctypes.c_uint64),
                ("ullHostTimestamp", ctypes.c_uint64),
                ("usCapabilityInformation", ctypes.c_uint16),
                ("ulChCenterFrequency", ctypes.c_uint32),
                ("wlanRateSet", ctypes.c_uint32 * 256),
                ("dot11DefaultAuthAlgorithm", ctypes.c_int),
                ("dot11DefaultCipherAlgorithm", ctypes.c_int),
                ("bDot11IEsPresent", ctypes.c_int)]


class WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [("dwTotalSize", ctypes.c_uint32),
                ("dwNumberOfItems", ctypes.c_uint32),
                ("wlanBssEntries", WLAN_BSS_ENTRY * 1)]


class WLAN_CONNECTION_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("isState", ctypes.c_int),
                ("wlanConnectionMode", ctypes.c_int),
                ("strProfileName", ctypes.c_wchar * WLAN_MAX_NAME_LENGTH),
                ("wlanAssociationAttributes", ctypes.c_ubyte * 64),
                ("wlanSecurityAttributes", ctypes.c_ubyte * 64)]


class WLAN_CONNECTION_ATTRIBUTES2(ctypes.Structure):
    _fields_ = [("isState", ctypes.c_int),
                ("wlanConnectionMode", ctypes.c_int),
                ("strProfileName", ctypes.c_wchar * WLAN_MAX_NAME_LENGTH),
                ("wlanAssociationAttributes", ctypes.c_ubyte * 64),
                ("wlanSecurityAttributes", ctypes.c_ubyte * 64)]


# ---------------------------------------------------------------- helpers
def _wifi_available() -> bool:
    return platform.system().lower() == "windows" and hasattr(ctypes, "windll")


def _open_handle(dll=None) -> Tuple[Optional[ctypes.c_void_p], Optional[int]]:
    if dll is None:
        try:
            dll = ctypes.windll.wlanapi
        except (OSError, AttributeError):
            return None, None
    h = ctypes.c_void_p()
    negotiated = ctypes.c_uint32()
    if not dll.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(h)):
        return h, negotiated.value
    return None, None


def _enum_interfaces(dll, h) -> Tuple[List[dict], List[ctypes.c_void_p]]:
    out = []
    interfaces = []
    if not dll or not h:
        return out, interfaces
    p = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
    if not dll.WlanEnumInterfaces(h, None, ctypes.byref(p)):
        return out, interfaces
    try:
        for i in range(p.contents.dwNumberOfItems):
            info = p.contents.InterfaceInfo[i]
            guid_bytes = bytes(info.InterfaceGuid)
            desc = info.strInterfaceDescription
            state = info.isState
            out.append({"index": info.InterfaceIndex, "guid": guid_bytes,
                        "description": desc, "state": state})
            # build GUID handle bytes
            guid = ctypes.c_ubyte * 16
            try:
                guid_handle = ctypes.cast(guid.from_buffer_copy(guid_bytes), ctypes.c_void_p)
            except Exception:
                guid_handle = None
            interfaces.append({"guid": guid_bytes, "handle": guid_handle,
                               "description": desc, "state": state})
    finally:
        try:
            dll.WlanFreeMemory(p)
        except Exception:
            pass
    return out, interfaces


def _ssid_from_dot11(dot11) -> str:
    try:
        length = dot11.uSSIDLength
        data = bytes(dot11.ucSSID[:length])
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _bssid_to_str(raw) -> str:
    try:
        parts = [f"{b:02X}" for b in bytes(raw)]
        return ":".join(parts)
    except Exception:
        return ""


def _quality_to_percentage(quality: int) -> int:
    return max(0, min(100, int(quality)))


def _channel_to_freq(channel: int, band_hint="") -> int:
    if band_hint == "2.4":
        return 2407 + channel * 5 if channel < 14 else 0
    if band_hint == "5":
        return 5000 + channel * 5
    if band_hint == "6":
        return 5950 + channel * 5
    # auto
    if 1 <= channel <= 13:
        return 2407 + channel * 5
    if 14 <= channel <= 165:
        return 5000 + channel * 5
    if channel >= 2:
        return 5950 + channel * 5
    return 0


def _freq_to_band(freq: int) -> str:
    if freq >= 7125:
        return "6"
    if 5170 <= freq <= 5895:
        return "5"
    if 2402 <= freq <= 2482:
        return "2.4"
    return "unknown"


def _auth_name(algo: int) -> str:
    mapping = {
        DOT11_AUTH_ALGO_OPEN: "Open",
        DOT11_AUTH_ALGO_SHARED: "Shared",
        DOT11_AUTH_ALGO_WPAPSK: "WPA-PSK",
        DOT11_AUTH_ALGO_WPA: "WPA",
        DOT11_AUTH_ALGO_WPA2: "WPA2",
        DOT11_AUTH_ALGO_WPA3: "WPA3",
        DOT11_AUTH_ALGO_RSNA: "RSNA",
    }
    return mapping.get(algo, f"Unknown({algo})")


def _cipher_name(algo: int) -> str:
    mapping = {
        0: "None",
        1: "WEP40",
        2: "TKIP",
        3: "CCMP",
        4: "WEP104",
        5: "GCMP",
        6: "CCMP-256",
        7: "GCMP-256",
    }
    return mapping.get(algo, f"Unknown({algo})")


def _phy_name(phy: int) -> str:
    return PHY_TYPE_NAMES.get(phy, f"Unknown({phy})")


def _band_from_phy(phy: int, freq: int) -> str:
    if phy in (DOT11_PHY_TYPE_HE, DOT11_PHY_TYPE_VHT, DOT11_PHY_TYPE_HT):
        # 6 GHz HE often maps to PHY HE but freq > 7125
        if freq >= 7125:
            return "6"
        if freq >= 5170:
            return "5"
        return "2.4"
    band = _freq_to_band(freq)
    return band


def _security_classify(auth: str, cipher: str) -> str:
    a = (auth or "").upper()
    c = (cipher or "").upper()
    if "OPEN" in a:
        return "Open"
    if "WPA3" in a or "WPA2/WPA3" in a:
        return "WPA3"
    if "WPA2" in a or "RSNA" in a:
        return "WPA2"
    if "WPA" in a or "PSK" in a:
        return "WPA"
    if "SHARED" in a or "WEP" in c:
        return "WEP"
    return "Unknown"


def _security_severity(security: str, cipher: str) -> Tuple[str, str]:
    """Return (severity, message) for security classification."""
    sec = (security or "").upper()
    if "OPEN" in sec:
        return "high", "Open network - no encryption."
    if "WEP" in sec:
        return "high", "WEP encryption is deprecated and easily broken."
    if "WPA" in sec and "WPA2" not in sec and "WPA3" not in sec:
        return "medium", "WPA (TKIP) is weak; use WPA2/WPA3."
    if "WPA3" in sec:
        return "info", "WPA3 - strong."
    if "WPA2" in sec:
        return "info", "WPA2 - acceptable."
    if "UNKNOWN" in sec:
        return "low", "Unknown security - verify manually."
    return "low", "Security could not be determined."


# ---------------------------------------------------------------- netsh fallback
def _run_netsh(args: List[str]) -> str:
    try:
        result = subprocess.run(["netsh"] + args, capture_output=True, text=True,
                                timeout=15, creationflags=0)
        return result.stdout + "\n" + result.stderr
    except (OSError, subprocess.SubprocessError) as exc:
        return f"netsh error: {exc}"


def _parse_netsh_interfaces(text: str) -> List[dict]:
    """Parse 'netsh wlan show interfaces' output (heuristic, best-effort)."""
    result = []
    current = {}
    for line in text.splitlines():
        s = line.strip()
        if ":" not in s:
            continue
        key, _, value = s.partition(":")
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if key.lower() in ("name", "description", "guid", "physical address", "state",
                            "ssid", "bssid", "radio type", "authentication", "cipher",
                            "channel", "receive rate", "transmit rate", "signal"):
            if key.lower() == "state" and current:
                result.append(current)
                current = {}
            current[key] = value
    if current:
        result.append(current)
    return result


def _parse_netsh_networks(text: str) -> List[dict]:
    """Parse 'netsh wlan show networks mode=bssid' output."""
    result = []
    current: dict = {}
    in_bssid = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("SSID ") and ":" in s:
            if current and current.get("ssid"):
                result.append(current)
            current = {"ssid": s.split(":", 1)[1].strip()}
            in_bssid = False
            continue
        if s.startswith("BSSID ") and ":" in s:
            current["bssid"] = s.split(":", 1)[1].strip()
            in_bssid = True
            continue
        if ":" not in s:
            continue
        key, _, value = s.partition(":")
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if in_bssid:
            if key == "Signal":
                try:
                    current["signal"] = int(value.split("%")[0])
                except ValueError:
                    pass
            elif key == "Radio type":
                current["radio_type"] = value
            elif key == "Channel":
                try:
                    current["channel"] = int(value)
                except ValueError:
                    pass
            elif key == "Basic rates (Mbps)":
                pass
            elif key == "Other rates (Mbps)":
                pass
            elif key == "Capability":
                current["capability"] = value
            elif key == "Type":
                current["bss_type"] = value
        else:
            if key == "Authentication":
                current.setdefault("authentication", value)
            elif key == "Encryption":
                current.setdefault("encryption", value)
    if current and current.get("ssid"):
        result.append(current)
    return result


# ---------------------------------------------------------------- public API
class WifiScanner:
    """Read-only Wi-Fi scanner (Windows Native API + netsh fallback)."""

    def __init__(self):
        self._available = _wifi_available()
        self._last_error: Optional[str] = None

    @property
    def available(self) -> bool:
        return self._available

    @property
    def last_error(self) -> Optional[str]:
        return self._last_error

    # -- adapter discovery
    def interfaces(self) -> List[dict]:
        if not self._available:
            return []
        dll = ctypes.windll.wlanapi
        h, _ = _open_handle(dll)
        if not h:
            return []
        try:
            raw, _ = _enum_interfaces(dll, h)
            return raw
        except Exception as exc:
            self._last_error = str(exc)
            return []
        finally:
            try:
                dll.WlanCloseHandle(h, None)
            except Exception:
                pass

    # -- connected adapter details
    def connected_info(self) -> dict:
        """Return details of the currently connected Wi-Fi adapter."""
        info = {
            "adapter": "", "ssid": "", "bssid": "", "signal": 0,
            "channel": 0, "frequency": 0, "band": "", "radio_type": "",
            "authentication": "", "cipher": "", "link_speed": 0,
            "state": "", "ip": "", "gateway": "", "dns": [],
        }
        if not self._available:
            return info
        try:
            dll = ctypes.windll.wlanapi
            h, _ = _open_handle(dll)
            if not h:
                return info
            try:
                # Enumerate interfaces, pick first connected one
                raw, ifaces = _enum_interfaces(dll, h)
                for iface in ifaces:
                    if iface.get("state") != 1:  # wlan_interface_state_connected == 1
                        continue
                    info["adapter"] = iface["description"]
                    # Query connection attributes
                    # (Simplified: full WlanQueryInterface call is complex; use netsh fallback)
                    break
            finally:
                dll.WlanCloseHandle(h, None)
        except Exception as exc:
            self._last_error = str(exc)
        # Fill with netsh data
        try:
            txt = _run_netsh(["wlan", "show", "interfaces"])
            parsed = _parse_netsh_interfaces(txt)
            for item in parsed:
                if item.get("state", "").lower() == "connected":
                    info.update({
                        "adapter": item.get("Name") or item.get("Description", info["adapter"]),
                        "ssid": item.get("SSID", info["ssid"]),
                        "bssid": item.get("BSSID", info["bssid"]),
                        "signal": _parse_int(item.get("Signal")),
                        "radio_type": item.get("Radio type", info["radio_type"]),
                        "authentication": item.get("Authentication", info["authentication"]),
                        "cipher": item.get("Cipher", info["cipher"]),
                        "channel": _parse_int(item.get("Channel")),
                    })
                    break
        except Exception:
            pass
        # IP / gateway / DNS via ipconfig
        try:
            out = _run_netsh(["interface", "ip", "show", "config"])
            info.update(_parse_ipconfig(out))
        except Exception:
            pass
        if info["channel"]:
            info["frequency"] = _channel_to_freq(info["channel"], info["band"])
            if not info["band"]:
                info["band"] = _freq_to_band(info["frequency"])
        return info

    # -- available networks (BSS list)
    def scan_networks(self) -> List[dict]:
        """Return list of available Wi-Fi networks (AP-level)."""
        networks: List[dict] = []
        if not self._available:
            return self._scan_netsh_networks()
        try:
            dll = ctypes.windll.wlanapi
            h, _ = _open_handle(dll)
            if not h:
                return self._scan_netsh_networks()
            try:
                raw, ifaces = _enum_interfaces(dll, h)
                for iface in ifaces:
                    if iface.get("state") != 1:
                        continue
                    p = ctypes.POINTER(WLAN_AVAILABLE_NETWORK_LIST)()
                    if dll.WlanGetAvailableNetworkList(h, ctypes.c_void_p(iface["guid"]),
                                                      0, None, ctypes.byref(p)):
                        continue
                    try:
                        for i in range(p.contents.dwNumberOfItems):
                            net = p.contents.Network[i]
                            ssid = _ssid_from_dot11(net.dot11Ssid)
                            auth = _auth_name(net.dot11DefaultAuthAlgorithm)
                            cipher = _cipher_name(net.dot11DefaultCipherAlgorithm)
                            phy = 0
                            freq = 0
                            band = ""
                            channel = 0
                            if net.uNumberOfPhyTypes > 0:
                                phy = net.dot11PhyTypes[0]
                            # Quality to RSSI approx
                            rssi = _quality_to_rssi(net.wlanSignalQuality)
                            networks.append({
                                "ssid": ssid,
                                "bssid": "",
                                "rssi": rssi,
                                "signal": _quality_to_percentage(net.wlanSignalQuality),
                                "channel": channel,
                                "frequency": freq,
                                "band": band,
                                "radio_type": _phy_name(phy),
                                "authentication": auth,
                                "cipher": cipher,
                                "connected": bool(net.bNetworkConnectable),
                            })
                    finally:
                        dll.WlanFreeMemory(p)
                    break  # only first connected adapter
            finally:
                dll.WlanCloseHandle(h, None)
        except Exception as exc:
            self._last_error = str(exc)
            return self._scan_netsh_networks()
        if not networks:
            return self._scan_netsh_networks()
        return networks

    def _scan_netsh_networks(self) -> List[dict]:
        """Fallback: parse 'netsh wlan show networks mode=bssid'."""
        try:
            txt = _run_netsh(["wlan", "show", "networks", "mode=bssid"])
            parsed = _parse_netsh_networks(txt)
            result = []
            for item in parsed:
                auth = item.get("authentication", "")
                cipher = item.get("encryption", "")
                sec = _security_classify(auth, cipher)
                freq = 0
                channel = item.get("channel", 0)
                if channel:
                    freq = _channel_to_freq(channel)
                band = _freq_to_band(freq) if freq else ""
                result.append({
                    "ssid": item.get("ssid", ""),
                    "bssid": item.get("bssid", ""),
                    "rssi": _signal_to_rssi(item.get("signal", 0)),
                    "signal": item.get("signal", 0),
                    "channel": channel,
                    "frequency": freq,
                    "band": band,
                    "radio_type": item.get("radio_type", ""),
                    "authentication": auth,
                    "cipher": cipher,
                    "security": sec,
                    "connected": False,
                })
            return result
        except Exception as exc:
            self._last_error = str(exc)
            return []

    # -- profiles
    def profiles(self) -> List[dict]:
        """Return saved Wi-Fi profiles (no credentials)."""
        if not self._available:
            return []
        try:
            dll = ctypes.windll.wlanapi
            h, _ = _open_handle(dll)
            if not h:
                return []
            try:
                p = ctypes.POINTER(WLAN_PROFILE_INFO_LIST)()
                if not dll.WlanGetProfileList(h, None, ctypes.byref(p)):
                    return []
                result = []
                for i in range(p.contents.dwNumberOfItems):
                    info = p.contents.ProfileInfo[i]
                    result.append({"name": info.strProfileName,
                                   "flags": info.dwFlags})
                dll.WlanFreeMemory(p)
                return result
            finally:
                dll.WlanCloseHandle(h, None)
        except Exception as exc:
            self._last_error = str(exc)
            return []

    def profile_names(self) -> List[str]:
        return [p["name"] for p in self.profiles()]

    # -- drivers
    def drivers(self) -> dict:
        try:
            txt = _run_netsh(["wlan", "show", "drivers"])
            return _parse_netsh_drivers(txt)
        except Exception as exc:
            self._last_error = str(exc)
            return {}

    def scan(self, ssid_filter: Optional[str] = None) -> List[dict]:
        """Trigger a scan and return fresh results (best-effort)."""
        # netsh scan trigger is unreliable; just re-query
        return self.scan_networks()


# ---------------------------------------------------------------- ip helpers
def _parse_int(value) -> int:
    try:
        if value is None:
            return 0
        s = str(value).strip()
        if s.endswith("%"):
            s = s[:-1]
        return int(float(s))
    except (ValueError, TypeError):
        return 0


def _parse_ipconfig(text: str) -> dict:
    """Extract IP, gateway, DNS from ipconfig output."""
    ip = gateway = ""
    dns = []
    current_adapter = ""
    in_wifi = False
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if not s.startswith(" "):
            current_adapter = s
            in_wifi = "Wireless" in s or "Wi-Fi" in s
            continue
        if not in_wifi:
            continue
        if "IPv4" in s or "IP Address" in s:
            ip = s.split(":", 1)[1].strip() if ":" in s else ip
        elif "Default Gateway" in s:
            gateway = s.split(":", 1)[1].strip() if ":" in s else gateway
        elif "DNS Servers" in s:
            dns_part = s.split(":", 1)[1].strip() if ":" in s else ""
            if dns_part:
                dns.append(dns_part)
            else:
                dns.append(s.split(".", 1)[1].strip() if "." in s else "")
    return {"ip": ip, "gateway": gateway, "dns": dns}


def _signal_to_rssi(signal_percent: int) -> int:
    try:
        p = max(0, min(100, int(signal_percent)))
        return int((p / 2) - 100)
    except (ValueError, TypeError):
        return -100


def _quality_to_rssi(quality: int) -> int:
    return _signal_to_rssi(quality)


def _parse_netsh_drivers(text: str) -> dict:
    result = {}
    for line in text.splitlines():
        s = line.strip()
        if ":" not in s:
            continue
        key, _, value = s.partition(":")
        key = key.strip()
        value = value.strip()
        if key:
            result[key] = value
    return result


# ---------------------------------------------------------------- convenience
def get_wifi_info() -> dict:
    """Convenience function returning connected Wi-Fi details."""
    scanner = WifiScanner()
    return scanner.connected_info()


def scan_wifi_networks(ssid_filter: Optional[str] = None) -> List[dict]:
    """Convenience function returning available Wi-Fi networks."""
    scanner = WifiScanner()
    networks = scanner.scan_networks()
    if ssid_filter:
        networks = [n for n in networks if ssid_filter.lower() in (n.get("ssid") or "").lower()]
    return networks


def get_wifi_profiles() -> List[str]:
    """Return saved Wi-Fi profile names."""
    scanner = WifiScanner()
    return scanner.profile_names()