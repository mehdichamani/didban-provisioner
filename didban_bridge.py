"""
Didban Bridge Module
Provides direct read-only access to Didban's SQLite database to dynamically fetch:
- NVR inventory (IPs, names, models, decrypted passwords)
- Used/allocated camera IPs (to prevent collisions during provisioning)
- Channels on target NVRs (detect free channels & attach new cameras)
"""

import os
import sys
import sqlite3
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Dict, List, Tuple
import urllib.request
import urllib.error

# Resolve paths
PROVISIONER_DIR = Path(__file__).resolve().parent
DIDBAN_DIR = PROVISIONER_DIR.parent
DIDBAN_DB_PATH = DIDBAN_DIR / "data" / "monitor.db"
ENCRYPTION_KEY_PATH = DIDBAN_DIR / "data" / "encryption.key"


def get_encryption_key() -> Optional[bytes]:
    """Reads encryption key from Didban data directory."""
    if ENCRYPTION_KEY_PATH.exists():
        try:
            return ENCRYPTION_KEY_PATH.read_bytes().strip()
        except Exception:
            return None
    return None


def decrypt_didban_password(encrypted_val: Optional[str]) -> str:
    """Decrypts AES-encrypted passwords stored by Didban using Fernet."""
    if not encrypted_val:
        return ""
    try:
        from cryptography.fernet import Fernet
        key = get_encryption_key()
        if key:
            f = Fernet(key)
            return f.decrypt(encrypted_val.encode()).decode()
    except Exception:
        pass
    return encrypted_val


def is_didban_available() -> bool:
    """Checks if Didban database is accessible."""
    return DIDBAN_DB_PATH.exists()


def get_nvrs_from_didban() -> List[Dict]:
    """
    Fetches all enabled NVRs from Didban database with decrypted credentials.
    """
    if not is_didban_available():
        return []

    try:
        # Use immutable/read-only URI connection to prevent DB locking
        conn = sqlite3.connect(f"file:{DIDBAN_DB_PATH.resolve()}?mode=ro", uri=True)
        cur = conn.cursor()
        rows = cur.execute(
            "SELECT ip, name, user, password, model, device_type FROM nvr WHERE enabled = 1"
        ).fetchall()
        conn.close()

        nvrs = []
        for r in rows:
            ip, name, user, enc_pass, model, dev_type = r
            nvrs.append({
                "ip": ip,
                "name": name or ip,
                "user": user or "admin",
                "password": decrypt_didban_password(enc_pass),
                "model": model or "NVR",
                "device_type": dev_type or "NVR"
            })
        return nvrs
    except Exception as e:
        print(f"[!] Warning: Failed to query NVRs from Didban database: {e}")
        return []


def get_all_registered_ips() -> set[str]:
    """
    Retrieves all camera and NVR IP addresses registered in Didban
    to avoid IP address collisions.
    """
    registered = set()
    if not is_didban_available():
        return registered

    try:
        conn = sqlite3.connect(f"file:{DIDBAN_DB_PATH.resolve()}?mode=ro", uri=True)
        cur = conn.cursor()
        
        # Get NVR IPs
        for r in cur.execute("SELECT ip FROM nvr").fetchall():
            if r[0]:
                registered.add(r[0].strip())
                
        # Get Camera IPs
        for r in cur.execute("SELECT ip FROM camera").fetchall():
            if r[0]:
                registered.add(r[0].strip())
                
        conn.close()
    except Exception as e:
        print(f"[!] Warning: Failed to query registered IPs from Didban: {e}")

    return registered


class HTTPDigestAuthHandlerCustom(urllib.request.HTTPDigestAuthHandler):
    """Custom digest handler if needed."""
    pass


def execute_isapi_request(
    ip: str,
    endpoint: str,
    user: str,
    password: str,
    method: str = "GET",
    data: Optional[bytes] = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 10.0
) -> Tuple[int, str]:
    """Sends authenticated ISAPI HTTP request (Digest Auth) via urllib."""
    url = f"http://{ip}{endpoint}"
    pwd_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    pwd_mgr.add_password(None, url, user, password)
    
    auth_handler = urllib.request.HTTPDigestAuthHandler(pwd_mgr)
    opener = urllib.request.build_opener(auth_handler)
    
    req = urllib.request.Request(url, data=data, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
            
    try:
        with opener.open(req, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body
    except Exception as e:
        return 0, str(e)


def get_nvr_channels_info(nvr_ip: str, user: str, password: str) -> Dict[int, Dict]:
    """
    Queries NVR for existing InputProxy channels via ISAPI.
    Returns dict: {channel_id: {"name": str, "ip": str, "online": bool}}
    """
    code, text = execute_isapi_request(
        nvr_ip,
        "/ISAPI/ContentMgmt/InputProxy/channels",
        user,
        password,
        method="GET"
    )
    if code != 200:
        return {}

    channels = {}
    try:
        root = ET.fromstring(text)
        ns = {"ns": "http://www.hikvision.com/ver20/XMLSchema"}
        for ch in root.findall(".//ns:InputProxyChannel", ns):
            cid_elem = ch.find("ns:id", ns)
            if cid_elem is None or not cid_elem.text:
                continue
            cid = int(cid_elem.text)
            cname = ch.find("ns:name", ns).text if ch.find("ns:name", ns) is not None else ""
            ip_elem = ch.find(".//ns:ipAddress", ns)
            cam_ip = ip_elem.text if ip_elem is not None else ""
            channels[cid] = {"name": cname, "ip": cam_ip}
    except Exception as e:
        print(f"[!] Error parsing NVR channels XML: {e}")

    return channels


def find_next_free_channel(occupied_channels: set[int], max_channels: int = 32) -> Optional[int]:
    """Returns the lowest free channel ID up to max_channels."""
    for ch_id in range(1, max_channels + 1):
        if ch_id not in occupied_channels:
            return ch_id
    return None


def add_camera_to_nvr(
    nvr_ip: str,
    nvr_user: str,
    nvr_password: str,
    channel_id: int,
    camera_name: str,
    camera_ip: str,
    camera_password: str,
    camera_port: int = 8000
) -> Tuple[bool, str]:
    """
    Adds an IP camera to the designated NVR channel via ISAPI POST / PUT.
    """
    xml_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<InputProxyChannel version="1.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
    <id>{channel_id}</id>
    <name>{camera_name}</name>
    <sourceInputPortDescriptor>
        <proxyProtocol>HIKVISION</proxyProtocol>
        <addressingFormatType>ipaddress</addressingFormatType>
        <ipAddress>{camera_ip}</ipAddress>
        <managePortNo>{camera_port}</managePortNo>
        <srcInputPort>1</srcInputPort>
        <userName>admin</userName>
        <password>{camera_password}</password>
        <streamType>auto</streamType>
    </sourceInputPortDescriptor>
    <enableTiming>true</enableTiming>
</InputProxyChannel>""".encode("utf-8")

    code, resp_text = execute_isapi_request(
        nvr_ip,
        "/ISAPI/ContentMgmt/InputProxy/channels",
        nvr_user,
        nvr_password,
        method="POST",
        data=xml_payload,
        headers={"Content-Type": "application/xml"},
        timeout=15.0
    )

    if code == 200 or "<statusCode>1</statusCode>" in resp_text:
        return True, "OK"
        
    # If channel slot exists or needs PUT:
    code_put, resp_put = execute_isapi_request(
        nvr_ip,
        f"/ISAPI/ContentMgmt/InputProxy/channels/{channel_id}",
        nvr_user,
        nvr_password,
        method="PUT",
        data=xml_payload,
        headers={"Content-Type": "application/xml"},
        timeout=15.0
    )
    if code_put == 200 or "<statusCode>1</statusCode>" in resp_put:
        return True, "OK"

    return False, f"Failed (POST {code}, PUT {code_put}): {resp_text or resp_put}"


def verify_camera_connection_status(
    nvr_ip: str,
    nvr_user: str,
    nvr_password: str,
    channel_id: int
) -> Tuple[bool, str]:
    """
    Checks if the added camera is online on the NVR.
    """
    code, text = execute_isapi_request(
        nvr_ip,
        "/ISAPI/ContentMgmt/InputProxy/channels/status",
        nvr_user,
        nvr_password,
        method="GET",
        timeout=10.0
    )
    if code != 200:
        return False, f"HTTP Error {code}"

    try:
        root = ET.fromstring(text)
        ns = {"ns": "http://www.hikvision.com/ver20/XMLSchema"}
        for ch in root.findall(".//ns:InputProxyChannelStatus", ns):
            cid_elem = ch.find("ns:id", ns)
            if cid_elem is not None and cid_elem.text == str(channel_id):
                online_elem = ch.find("ns:online", ns)
                res_elem = ch.find("ns:chanDetectResult", ns)
                is_online = online_elem is not None and online_elem.text.lower() == "true"
                result_str = res_elem.text if res_elem is not None else "unknown"
                return is_online, result_str
    except Exception as e:
        return False, f"Parse error: {e}"

    return False, "Channel not found in status list"
