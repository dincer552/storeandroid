"""Read-only Windows Event Log access for login audit, WLAN history and NPS.

Uses ``wevtutil`` (available on all Windows 10/11 systems) to query event XML.
No audit policy, Group Policy or security configuration is modified.

Security scope: read-only.  Credential material, passwords and secrets are
never extracted - only event metadata needed for the security timeline.
"""
import json
import platform
import re
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}

INTERACTIVE_LOGON_TYPES = {"2", "7", "10", "11"}

# Windows Event IDs of interest.
LOGIN_EVENTS = {4624: "Successful Logon", 4625: "Failed Logon",
                4634: "Session Terminated", 4647: "User Initiated Logoff",
                4648: "Explicit Credentials"}

NPS_EVENTS = {6272: "Access Granted", 6273: "Access Denied", 6274: "Request Discarded"}


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _run_wevtutil(args: List[str], timeout=20) -> str:
    try:
        result = subprocess.run(
            ["wevtutil"] + args, capture_output=True, text=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if _is_windows() else 0)
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _query_xml(log_name: str, xpath: str, max_events: int = 200) -> str:
    """Return raw XML for events matching the xpath filter."""
    args = ["qe", log_name, f"/q:{xpath}", f"/c:{int(max_events)}",
            "/rd:true", "/f:xml"]
    return _run_wevtutil(args)


def _iter_events(xml_text: str):
    """Yield (event_id, timestamp, data_dict) from concatenated event XML."""
    if not xml_text:
        return
    # wevtutil may return multiple concatenated <Event> docs; wrap in a root.
    wrapped = "<Events>" + xml_text + "</Events>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError:
        # attempt to split on </Event> boundaries
        docs = re.findall(r"<Event\b.*?</Event>", xml_text, re.DOTALL)
        for doc in docs:
            try:
                root_elem = ET.fromstring(doc)
            except ET.ParseError:
                continue
            yield from _parse_event_element(root_elem)
        return
    for event in root:
        yield from _parse_event_element(event)


def _parse_event_element(event) -> List[tuple]:
    try:
        system = event.find(f"{NS}System")
        if system is None:
            return []
        event_id_el = system.find(f"{NS}EventID")
        event_id = int(event_id_el.text) if event_id_el is not None and event_id_el.text else 0
        time_el = system.find(f"{NS}TimeCreated")
        timestamp = 0.0
        if time_el is not None:
            sys_time = time_el.get("SystemTime")
            if sys_time:
                timestamp = _parse_iso_time(sys_time)
        data = {}
        event_data = event.find(f"{NS}EventData")
        if event_data is not None:
            for item in event_data:
                name = item.get("Name")
                if name:
                    data[name] = item.text or ""
        return [(event_id, timestamp, data)]
    except Exception:
        return []


def _parse_iso_time(value: str) -> float:
    try:
        # e.g. 2024-01-01T12:34:56.7890123Z
        cleaned = value.replace("Z", "+00:00")
        # Trim fractional seconds to 6 digits for fromisoformat
        m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})", value)
        if m:
            base, frac, tz = m.group(1), m.group(2), m.group(3)
            if frac:
                frac = "." + frac[1:7].ljust(6, "0")
            else:
                frac = ""
            tz = "+00:00" if tz == "Z" else tz
            cleaned = base + frac + tz
        return datetime.fromisoformat(cleaned).timestamp()
    except Exception:
        return 0.0


# ---------------------------------------------------------------- login audit
def get_login_events(start: float = 0.0, max_events: int = 200) -> List[dict]:
    """Return parsed Security log login/logoff events."""
    if not _is_windows():
        return []
    since = datetime.fromtimestamp(start or (datetime.now().timestamp() - 86400),
                                   tz=timezone.utc)
    since_str = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    # Combined xpath for supported event IDs
    event_ids = ",".join(str(e) for e in LOGIN_EVENTS)
    xpath = (f"*[System[({_ID_FILTER(event_ids)}) and "
             f"TimeCreated[@SystemTime>='{since_str}']]]")
    xml_text = _query_xml("Security", xpath, max_events)
    results = []
    for event_id, timestamp, data in _iter_events(xml_text):
        if event_id not in LOGIN_EVENTS:
            continue
        results.append(_normalise_login_event(event_id, timestamp, data))
    return results


def _ID_FILTER(ids: str) -> str:
    parts = " or ".join(f"EventID={i}" for i in ids.split(","))
    return parts


def _normalise_login_event(event_id: int, timestamp: float, data: dict) -> dict:
    logon_type = str(data.get("LogonType", ""))
    logon_type_name = LOGON_TYPES.get(logon_type, "")
    interactive = logon_type in INTERACTIVE_LOGON_TYPES
    username = data.get("TargetUserName") or data.get("SubjectUserName") or ""
    domain = data.get("TargetDomainName") or data.get("SubjectDomainName") or ""
    sid = data.get("TargetUserSid") or data.get("SubjectUserSid") or ""
    logon_id = data.get("TargetLogonId") or data.get("SubjectLogonId") or ""
    source_ws = data.get("WorkstationName", "")
    source_ip = data.get("IpAddress", "")
    process = data.get("ProcessName", "")
    auth_pkg = data.get("AuthenticationPackageName", "")
    failure_status = data.get("Status", "") if event_id == 4625 else ""
    failure_reason = data.get("SubStatus", "") if event_id == 4625 else ""
    return {
        "event_id": event_id,
        "event_name": LOGIN_EVENTS.get(event_id, str(event_id)),
        "timestamp": timestamp,
        "username": username,
        "domain": domain,
        "sid": sid,
        "logon_id": logon_id,
        "logon_type": logon_type,
        "logon_type_name": logon_type_name,
        "source_workstation": source_ws,
        "source_ip": source_ip,
        "process": process,
        "auth_package": auth_pkg,
        "failure_status": failure_status,
        "failure_reason": failure_reason,
        "interactive": interactive,
        "source": "windows-security",
    }


def correlate_sessions(events: List[dict]) -> List[dict]:
    """Correlate 4624 with 4634/4647 via Logon ID. Returns session dicts."""
    sessions: Dict[str, dict] = {}
    terminated = {}
    for ev in events:
        eid = ev.get("event_id")
        lid = ev.get("logon_id") or ""
        if not lid:
            continue
        if eid == 4624:
            sessions[lid] = {
                "logon_id": lid,
                "username": ev.get("username"),
                "domain": ev.get("domain"),
                "logon_time": ev.get("timestamp"),
                "logon_type": ev.get("logon_type"),
                "logon_type_name": ev.get("logon_type_name"),
                "interactive": ev.get("interactive"),
                "logoff_time": None,
                "status": "open",
            }
        elif eid in (4634, 4647):
            terminated[lid] = ev.get("timestamp")
    for lid, t in terminated.items():
        if lid in sessions:
            sessions[lid]["logoff_time"] = t
            sessions[lid]["status"] = "closed"
    return list(sessions.values())


# ---------------------------------------------------------------- WLAN events
def get_wlan_events(start: float = 0.0, max_events: int = 200) -> List[dict]:
    """Return WLAN-AutoConfig operational events."""
    if not _is_windows():
        return []
    log_name = "Microsoft-Windows-WLAN-AutoConfig/Operational"
    since = datetime.fromtimestamp(start or (datetime.now().timestamp() - 86400),
                                   tz=timezone.utc)
    since_str = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    xpath = f"*[System[TimeCreated[@SystemTime>='{since_str}']]]"
    xml_text = _query_xml(log_name, xpath, max_events)
    results = []
    for event_id, timestamp, data in _iter_events(xml_text):
        results.append(_normalise_wlan_event(event_id, timestamp, data))
    return results


WLAN_EVENT_TYPES = {
    8001: "Connection", 8002: "Connection Failure", 8003: "Disconnect",
    12011: "Association", 12012: "Authentication", 12013: "Roaming",
    11000: "Start", 11001: "Stop",
}


def _normalise_wlan_event(event_id: int, timestamp: float, data: dict) -> dict:
    ssid = data.get("SSID") or data.get("Ssid") or ""
    bssid = data.get("BSSID") or data.get("Bssid") or data.get("AP") or ""
    adapter = data.get("Adapter") or data.get("InterfaceDescription") or ""
    reason = data.get("Reason") or data.get("FailureReason") or ""
    return {
        "event_id": event_id,
        "event_type": WLAN_EVENT_TYPES.get(event_id, f"Event {event_id}"),
        "timestamp": timestamp,
        "ssid": ssid,
        "bssid": bssid,
        "adapter": adapter,
        "reason": reason,
        "source": "wlan-autoconfig",
        "raw": data,
    }


# ---------------------------------------------------------------- NPS / RADIUS
def get_nps_events(start: float = 0.0, max_events: int = 200) -> List[dict]:
    """Return NPS (IAS) authentication events if the log exists."""
    if not _is_windows():
        return []
    logs = ["Security", "System"]
    since = datetime.fromtimestamp(start or (datetime.now().timestamp() - 86400),
                                   tz=timezone.utc)
    since_str = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    results = []
    for log in logs:
        ids = ",".join(str(e) for e in NPS_EVENTS)
        xpath = (f"*[System[({_ID_FILTER(ids)}) and "
                 f"TimeCreated[@SystemTime>='{since_str}']]]")
        xml_text = _query_xml(log, xpath, max_events)
        for event_id, timestamp, data in _iter_events(xml_text):
            if event_id not in NPS_EVENTS:
                continue
            results.append(_normalise_nps_event(event_id, timestamp, data))
    return results


def _normalise_nps_event(event_id: int, timestamp: float, data: dict) -> dict:
    return {
        "event_id": event_id,
        "event_name": NPS_EVENTS.get(event_id, str(event_id)),
        "timestamp": timestamp,
        "username": data.get("User") or data.get("TargetUserName") or "",
        "domain": data.get("Domain") or "",
        "radius_client": data.get("ClientFriendlyName") or data.get("Client-Name") or "",
        "client_ip": data.get("ClientIPAddress") or data.get("Client-IP-Address") or "",
        "auth_type": data.get("Authentication-Type") or data.get("AuthenticationProvider") or "",
        "network_policy": data.get("Policy-Name") or data.get("NetworkPolicyName") or "",
        "failure_reason": data.get("Reason-String") or data.get("Reason") or "",
        "source": "nps",
    }


def nps_available() -> bool:
    """Best-effort check whether NPS/IAS events can be found."""
    if not _is_windows():
        return False
    try:
        txt = _run_wevtutil(["gl", "System"])
        # NPS logs events into Security/System only if installed
        return bool(txt)
    except Exception:
        return False


def audit_available() -> Tuple[bool, str]:
    """Check whether the Security log is readable.

    Returns (available, message).
    """
    if not _is_windows():
        return False, "Windows Event Log yalnızca Windows üzerinde kullanılabilir."
    try:
        txt = _run_wevtutil(["gli", "Security"])
        if not txt or "error" in txt.lower() and "access" in txt.lower():
            return False, ("Security log okunamadı. Yönetici olarak çalıştırın veya "
                           "olay günlüğü izinlerini kontrol edin.")
        return True, "Security log erişilebilir."
    except Exception as exc:
        return False, f"Security log erişim hatası: {exc}"

class WindowsEventLog:
    """Class wrapper around the module-level event helpers.

    Provides a stable object-oriented API for the UI layer while the
    implementation remains the read-only module functions above.
    """

    @staticmethod
    def get_login_events(start: float = 0.0, max_events: int = 200) -> List[dict]:
        return get_login_events(start, max_events)

    @staticmethod
    def get_wlan_events(start: float = 0.0, max_events: int = 200) -> List[dict]:
        return get_wlan_events(start, max_events)

    @staticmethod
    def get_nps_events(start: float = 0.0, max_events: int = 200) -> List[dict]:
        return get_nps_events(start, max_events)

    @staticmethod
    def correlate_sessions(events: List[dict]) -> List[dict]:
        return correlate_sessions(events)

    @staticmethod
    def audit_available() -> Tuple[bool, str]:
        return audit_available()

    @staticmethod
    def nps_available() -> bool:
        return nps_available()
