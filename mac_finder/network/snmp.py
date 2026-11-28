"""Minimal read-only SNMP client (v1/v2c) plus optional SNMPv3 via pysnmp.

Scope and safety:
- Only GET / GETNEXT (walk) operations are supported.
- No SET / configuration changes.
- SNMPv3 preferred config is SHA-2 auth + AES-128 privacy when pysnmp is present.
- Credentials are never written to disk by this module.

If no SNMP agent is reachable the module raises a clear error; callers show
"Bilinmiyor" rather than fabricating values.
"""
import random
import socket
import struct
from typing import Any, Dict, List, Optional


# Standard OIDs (SNMPv2-MIB / IF-MIB)
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
OID_IF_ADMIN = "1.3.6.1.2.1.2.2.1.7"
OID_IF_OPER = "1.3.6.1.2.1.2.2.1.8"
OID_IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
OID_IF_IN_ERRORS = "1.3.6.1.2.1.2.2.1.14"
OID_IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"
OID_IF_OUT_ERRORS = "1.3.6.1.2.1.2.2.1.20"
OID_IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IF_HIGH_SPEED = "1.3.6.1.2.1.31.1.1.1.15"


# --------------------------------------------------------------------------- BER
def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(payload)) + payload


def _encode_integer(value: int, tag: int = 0x02) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        length = (value.bit_length() + 8) // 8
        body = value.to_bytes(length, "big", signed=True)
        # Strip redundant leading sign bytes
        while len(body) > 1 and body[0] == 0x00 and not (body[1] & 0x80):
            body = body[1:]
        while len(body) > 1 and body[0] == 0xFF and (body[1] & 0x80):
            body = body[1:]
    return _tlv(tag, body)


def _encode_octet_string(value: bytes, tag: int = 0x04) -> bytes:
    return _tlv(tag, value)


def _encode_null() -> bytes:
    return b"\x05\x00"


def _encode_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.strip().split(".")]
    if len(parts) < 2:
        raise ValueError("Invalid OID")
    body = bytes([parts[0] * 40 + parts[1]])
    for number in parts[2:]:
        if number < 0x80:
            body += bytes([number])
        else:
            chunks = []
            while number:
                chunks.append(number & 0x7F)
                number >>= 7
            chunks.reverse()
            for i, chunk in enumerate(chunks):
                body += bytes([chunk | (0x80 if i < len(chunks) - 1 else 0)])
    return _tlv(0x06, body)


def _decode_tlv(data: bytes, offset: int = 0):
    tag = data[offset]
    length = data[offset + 1]
    cursor = offset + 2
    if length & 0x80:
        nbytes = length & 0x7F
        length = int.from_bytes(data[cursor:cursor + nbytes], "big")
        cursor += nbytes
    value = data[cursor:cursor + length]
    return tag, value, cursor + length


def _decode_integer(value: bytes) -> int:
    return int.from_bytes(value, "big", signed=True)


def _decode_oid(value: bytes) -> str:
    if not value:
        return ""
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    number = 0
    for byte in value[1:]:
        number = (number << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(number))
            number = 0
    return ".".join(parts)


def _decode_value(tag: int, value: bytes) -> Any:
    if tag == 0x02:  # INTEGER
        return _decode_integer(value)
    if tag == 0x04:  # OCTET STRING
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return value.hex()
    if tag == 0x06:  # OID
        return _decode_oid(value)
    if tag == 0x43:  # TimeTicks
        ticks = _decode_integer(value) if value else 0
        total_seconds = ticks // 100
        days, rem = divmod(total_seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, seconds = divmod(rem, 60)
        return f"{days}d {hours}h {minutes}m {seconds}s"
    if tag in (0x41, 0x42, 0x44, 0x46):  # Counter/Gauge/IP/etc.
        return _decode_integer(value) if value else 0
    if tag == 0x05:  # NULL
        return None
    return value.hex()


class SnmpError(RuntimeError):
    """Raised when an SNMP query cannot be completed."""


class SnmpClient:
    """Read-only SNMP v1/v2c client using raw UDP. SNMPv3 requires pysnmp."""

    def __init__(self, host: str, credential: str = "public", version: int = 2,
                 port: int = 161, timeout: float = 2.0, retries: int = 1):
        self.host = host
        self.credential = credential or "public"
        self.version = version if version in (1, 2) else 2
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self._request_id = random.randint(1, 0x7FFFFFFF)

    # -- low level --------------------------------------------------------
    def _build_message(self, oid: str, request_type: int) -> bytes:
        self._request_id += 1
        varbind = _tlv(0x30, _encode_oid(oid) + _encode_null())
        varbind_list = _tlv(0x30, varbind)
        pdu_body = (
            _encode_integer(self._request_id)
            + _encode_integer(0)  # error-status
            + _encode_integer(0)  # error-index
            + varbind_list
        )
        pdu = _tlv(request_type, pdu_body)  # 0xA0 GET, 0xA1 GETNEXT
        version = 0 if self.version == 1 else 1
        message_body = (
            _encode_integer(version)
            + _encode_octet_string(self.credential.encode("utf-8"))
            + pdu
        )
        return _tlv(0x30, message_body)

    def _send(self, payload: bytes) -> bytes:
        family = socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(self.timeout)
            last_error = None
            for _ in range(self.retries + 1):
                try:
                    sock.sendto(payload, (self.host, self.port))
                    data, _ = sock.recvfrom(65535)
                    return data
                except socket.timeout as exc:
                    last_error = exc
                except OSError as exc:
                    last_error = exc
            raise SnmpError(f"SNMP timeout/connection error for {self.host}: {last_error}")

    def _parse_response(self, data: bytes) -> Dict[str, Any]:
        try:
            _, msg, _ = _decode_tlv(data, 0)
            offset = 0
            _, _, offset = _decode_tlv(msg, offset)       # version
            _, _, offset = _decode_tlv(msg, offset)       # community
            tag, pdu, _ = _decode_tlv(msg, offset)        # PDU
            p = 0
            _, req_bytes, p = _decode_tlv(pdu, p)
            request_id = _decode_integer(req_bytes) if req_bytes else None
            _, err_bytes, p = _decode_tlv(pdu, p)
            error_status = _decode_integer(err_bytes) if err_bytes else 0
            _, _, p = _decode_tlv(pdu, p)                  # error index
            _, vbl_bytes, p = _decode_tlv(pdu, p)          # varbind list
            # first varbind
            _, vb, _ = _decode_tlv(vbl_bytes, 0)
            _, oid_bytes, q = _decode_tlv(vb, 0)
            val_tag, val_bytes, _ = _decode_tlv(vb, q)
            return {
                "request_id": request_id,
                "error_status": error_status,
                "oid": _decode_oid(oid_bytes),
                "value": _decode_value(val_tag, val_bytes),
                "end_of_mib": val_tag == 0x80,
            }
        except (IndexError, ValueError) as exc:
            raise SnmpError(f"Malformed SNMP response: {exc}")

    # -- public API -------------------------------------------------------
    def get(self, oid: str) -> Any:
        response = self._parse_response(self._send(self._build_message(oid, 0xA0)))
        if response.get("error_status"):
            raise SnmpError(f"SNMP error status {response['error_status']} for OID {oid}")
        return response.get("value")

    def get_next(self, oid: str) -> Dict[str, Any]:
        return self._parse_response(self._send(self._build_message(oid, 0xA1)))

    def walk(self, base_oid: str, max_rows: int = 512) -> List[Dict[str, Any]]:
        results = []
        current = base_oid
        for _ in range(max_rows):
            response = self.get_next(current)
            if response.get("end_of_mib") or response.get("error_status"):
                break
            next_oid = response.get("oid", "")
            if not next_oid.startswith(base_oid + "."):
                break
            results.append({"oid": next_oid, "value": response.get("value")})
            current = next_oid
        return results

    def system_info(self) -> Dict[str, Any]:
        """Return sysDescr/sysName/sysUpTime plus a compact interface list."""
        info: Dict[str, Any] = {}
        for key, oid in (("sysDescr", OID_SYS_DESCR),
                         ("sysName", OID_SYS_NAME),
                         ("sysUpTime", OID_SYS_UPTIME)):
            try:
                info[key] = self.get(oid)
            except (SnmpError, OSError):
                info[key] = "Bilinmiyor"

        interfaces = self._interface_table()
        info["interfaces"] = interfaces
        return info

    def _interface_table(self) -> List[Dict[str, Any]]:
        """Assemble interface rows from IF-MIB walks keyed by ifIndex."""
        rows: Dict[str, Dict[str, Any]] = {}
        tables = {
            "ifName": OID_IF_NAME,
            "ifDescr": OID_IF_DESCR,
            "ifAdminStatus": OID_IF_ADMIN,
            "ifOperStatus": OID_IF_OPER,
            "ifSpeed": OID_IF_SPEED,
            "ifHighSpeed": OID_IF_HIGH_SPEED,
            "ifInOctets": OID_IF_IN_OCTETS,
            "ifOutOctets": OID_IF_OUT_OCTETS,
            "ifInErrors": OID_IF_IN_ERRORS,
            "ifOutErrors": OID_IF_OUT_ERRORS,
        }
        for field, oid in tables.items():
            try:
                for entry in self.walk(oid):
                    index = entry["oid"][len(oid) + 1:]
                    rows.setdefault(index, {"ifIndex": index})[field] = entry["value"]
            except (SnmpError, OSError):
                continue
        return [rows[k] for k in sorted(rows, key=lambda x: int(x) if x.isdigit() else x)]


# --------------------------------------------------------------------------- v3
def snmp_v3_available() -> bool:
    try:
        import pysnmp  # noqa: F401
        return True
    except Exception:  # noqa: BLE001
        return False


def query_v3(host: str, username: str, auth_key: str, priv_key: str,
             auth_protocol: str = "SHA-256", priv_protocol: str = "AES-128",
             oid: str = OID_SYS_DESCR, timeout: float = 2.0) -> Dict[str, Any]:
    """SNMPv3 GET via pysnmp when installed. Returns a dict or raises SnmpError."""
    try:
        from pysnmp.hlapi import (  # type: ignore
            SnmpEngine, UsmUserData, UdpTransportTarget, ContextData,
            ObjectType, ObjectIdentity, getCmd,
            usmHMACSHAAuthProtocol, usmAesCfb128Protocol,
        )
    except Exception as exc:  # noqa: BLE001
        raise SnmpError(
            "SNMPv3 için 'pysnmp' paketi gerekir (pip install pysnmp). "
            "Paket yoksa SNMPv1/v2c kullanın."
        ) from exc

    auth_map = {"SHA-256": usmHMACSHAAuthProtocol, "SHA": usmHMACSHAAuthProtocol}
    priv_map = {"AES-128": usmAesCfb128Protocol, "AES": usmAesCfb128Protocol}
    user = UsmUserData(
        username, authKey=auth_key, privKey=priv_key,
        authProtocol=auth_map.get(auth_protocol.upper(), usmHMACSHAAuthProtocol),
        privProtocol=priv_map.get(priv_protocol.upper(), usmAesCfb128Protocol),
    )
    transport = UdpTransportTarget((host, 161), timeout=timeout, retries=1)
    iterator = getCmd(SnmpEngine(), user, transport, ContextData(),
                      ObjectType(ObjectIdentity(oid)))
    error_indication, error_status, _err_index, var_binds = next(iterator)
    if error_indication:
        raise SnmpError(str(error_indication))
    if error_status:
        raise SnmpError(error_status.prettyPrint())
    return {"oid": oid, "value": var_binds[0][1].prettyPrint()}