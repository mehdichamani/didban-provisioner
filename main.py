#!/usr/bin/env python3
"""
Didban Provisioner: Hikvision Batch Provisioner & NVR Onboarding for Linux
Discovers unactivated cameras (192.168.1.64) via L2 ARP, reserves DHCP IP
on Mikrotik, activates via RSA/AES ISAPI handshake, and automatically/interactively
attaches newly provisioned cameras to NVRs discovered from Didban database.
"""

import os
import sys
import time
import base64
import re
import socket
import subprocess
import urllib.request
import urllib.error
import ipaddress
from pathlib import Path

# Cryptography & Packet craft
try:
    from scapy.all import Ether, ARP, srp
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from Crypto.Cipher import AES
except ImportError as e:
    print(f"Error: Missing dependency ({e}).")
    print("Please install dependencies: uv sync")
    sys.exit(1)

# Import Didban Bridge
import didban_bridge as db_bridge


def load_env(env_path: Path):
    config = {}
    if not env_path.exists():
        return config
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip().strip("\"'")
    return config


BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"
CFG = load_env(ENV_FILE)

VLAN_INTERFACE = CFG.get("VLAN_INTERFACE", "eno1.400")
ROUTER_HOST = CFG.get("ROUTER_HOST", "router-pishgaman")
ROUTER_USER = CFG.get("ROUTER_USER", "")
DHCP_SERVER = CFG.get("DHCP_SERVER_NAME", "server1")
CAMERA_PASSWORD = CFG.get("CAMERA_PASSWORD", "@Aa3603912!")
IP_POOL_NAME = CFG.get("IP_POOL_NAME", "pool-cameras")


def run_router_cmd(command: str) -> str:
    """Executes a command on the Mikrotik router via SSH."""
    ssh_target = f"{ROUTER_USER}@{ROUTER_HOST}" if ROUTER_USER else ROUTER_HOST
    orig_user = os.environ.get("SUDO_USER")
    
    ssh_cmd = f'ssh -o BatchMode=yes -o ConnectTimeout=6 {ssh_target} "{command}"'
    if orig_user and orig_user != "root":
        cmd = ["su", orig_user, "-c", ssh_cmd]
    else:
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", ssh_target, command]

    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        return res.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"[!] Mikrotik command failed: {e.stderr.strip()}")
        raise


def get_local_mac(iface: str) -> str:
    """Finds the local MAC address for the given interface."""
    try:
        with open(f"/sys/class/net/{iface}/address", "r") as f:
            return f.read().strip()
    except Exception:
        return "00:15:5d:01:c8:05"


def scan_unconfigured_cameras(iface: str):
    """Scans for unconfigured cameras sitting on 192.168.1.64 via L2 broadcast ARP."""
    print(f"[*] Scanning for inactive Hikvision cameras on {iface} (192.168.1.64)...")
    my_mac = get_local_mac(iface)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac) / ARP(
        op=1, hwsrc=my_mac, psrc="192.168.1.200", pdst="192.168.1.64"
    )
    ans, _ = srp(pkt, iface=iface, timeout=3.0, verbose=False, multi=True)

    cams = []
    seen = set()
    for _, rcv in ans:
        mac = rcv[Ether].src.lower()
        if mac not in seen:
            seen.add(mac)
            cams.append(mac)
    return cams


def get_pool_range(pool_name: str) -> tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]:
    """Queries Mikrotik for the IP range of the given pool."""
    if not pool_name:
        raise ValueError("IP_POOL_NAME is not set. Please specify the pool name.")

    print(f"[*] Querying IP pool '{pool_name}' from Mikrotik router...")
    out = run_router_cmd(f'/ip/pool/print detail where name="{pool_name}"')
    m = re.search(r"ranges=([0-9.]+)-([0-9.]+)", out)
    if not m:
        raise RuntimeError(f"Could not find or parse ranges for pool '{pool_name}' on Mikrotik:\n{out}")

    start_ip = ipaddress.IPv4Address(m.group(1))
    end_ip = ipaddress.IPv4Address(m.group(2))
    return start_ip, end_ip


def get_used_ips_from_leases(start_ip: ipaddress.IPv4Address, end_ip: ipaddress.IPv4Address) -> set[ipaddress.IPv4Address]:
    """Retrieves all allocated lease addresses that fall within the pool range."""
    leases_out = run_router_cmd("/ip/dhcp-server/lease/print detail")
    found_ips = re.findall(r"(?:active-address|address)=([0-9.]+)", leases_out)
    used = set()
    for ip_str in found_ips:
        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
            if start_ip <= ip_obj <= end_ip:
                used.add(ip_obj)
        except ValueError:
            continue

    # Also add Didban registered IPs to guarantee zero IP collisions
    didban_ips = db_bridge.get_all_registered_ips()
    for ip_str in didban_ips:
        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
            if start_ip <= ip_obj <= end_ip:
                used.add(ip_obj)
        except ValueError:
            continue

    return used


def get_next_available_ip(start_ip: ipaddress.IPv4Address, end_ip: ipaddress.IPv4Address, used_ips: set[ipaddress.IPv4Address]) -> ipaddress.IPv4Address:
    curr = start_ip
    while curr <= end_ip:
        if curr not in used_ips:
            return curr
        curr += 1
    raise RuntimeError("No available IP addresses in the pool!")


def setup_temp_bridge_nat():
    """Sets up temporary NAT on Mikrotik to access 192.168.1.64 via 172.20.0.1:8080."""
    print("[*] Setting up temporary Mikrotik NAT for 192.168.1.64...")
    run_router_cmd('/ip firewall nat add chain=dstnat dst-address=172.20.0.1 protocol=tcp dst-port=8080 action=dst-nat to-addresses=192.168.1.64 to-ports=80 comment="TEMP_DIDBAN_PROVISIONER"')
    run_router_cmd('/ip firewall nat add chain=srcnat dst-address=192.168.1.64 action=masquerade comment="TEMP_DIDBAN_PROVISIONER"')


def cleanup_temp_bridge_nat():
    """Removes temporary NAT rules."""
    print("[*] Cleaning up temporary Mikrotik NAT...")
    try:
        run_router_cmd('/ip firewall nat remove [find comment="TEMP_DIDBAN_PROVISIONER"]')
    except Exception:
        pass


def activate_camera(target_url: str, password: str):
    """Executes Hikvision RSA/AES handshake to activate camera."""
    sec_cap_url = f"{target_url}/ISAPI/Security/capabilities"
    req = urllib.request.Request(sec_cap_url)
    with urllib.request.urlopen(req, timeout=5) as response:
        content = response.read().decode("utf-8")

    m_key = re.search(r"<key>([^<]+)</key>", content)
    m_challenge = re.search(r"<challenge>([^<]+)</challenge>", content)
    if not m_key or not m_challenge:
        raise ValueError("Could not extract RSA key or challenge from camera capabilities.")

    raw_key = m_key.group(1).strip()
    challenge = m_challenge.group(1).strip()

    aes_key = os.urandom(16)
    cipher_aes = AES.new(aes_key, AES.MODE_ECB)
    pad_len = 16 - (len(password) % 16)
    padded_pass = password.encode() + bytes([pad_len]) * pad_len
    enc_password = base64.b64encode(cipher_aes.encrypt(padded_pass)).decode()

    clean_pem = "\n".join(raw_key.strip().split("\n")[1:-1])
    key_bytes = base64.b64decode(clean_pem)

    def parse_public_key_rsa(der_data):
        pos = 0
        def read_len(p):
            l = der_data[p]
            if l < 0x80:
                return l, p + 1
            n_bytes = l & 0x7F
            val = 0
            p += 1
            for _ in range(n_bytes):
                val = (val << 8) | der_data[p]
                p += 1
            return val, p

        assert der_data[pos] == 0x30
        pos += 1
        _, pos = read_len(pos)
        assert der_data[pos] == 0x30
        pos += 1
        _, pos = read_len(pos)
        while der_data[pos] != 0x03:
            pos += 1
        pos += 1
        _, pos = read_len(pos)
        pos += 1  # unused bits
        assert der_data[pos] == 0x30
        pos += 1
        _, pos = read_len(pos)
        assert der_data[pos] == 0x02
        pos += 1
        mod_len, pos = read_len(pos)
        modulus = int.from_bytes(der_data[pos:pos+mod_len], 'big')
        pos += mod_len
        assert der_data[pos] == 0x02
        pos += 1
        exp_len, pos = read_len(pos)
        exponent = int.from_bytes(der_data[pos:pos+exp_len], 'big')
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()

    pub_key = parse_public_key_rsa(key_bytes)
    data_to_rsa = (challenge + ":" + base64.b64encode(aes_key).decode()).encode()
    enc_key = base64.b64encode(pub_key.encrypt(data_to_rsa, padding.PKCS1v15())).decode()

    activate_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<ActivateInfo version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
    <password>{enc_password}</password>
    <key>{enc_key}</key>
</ActivateInfo>"""

    act_url = f"{target_url}/ISAPI/System/activate"
    req = urllib.request.Request(act_url, data=activate_xml.encode("utf-8"), headers={"Content-Type": "application/xml"}, method="PUT")
    with urllib.request.urlopen(req, timeout=5) as response:
        resp = response.read().decode("utf-8")
        if "<statusCode>1</statusCode>" not in resp and "OK" not in resp:
            raise RuntimeError(f"Activation failed: {resp}")


def set_dhcp_and_reboot(target_url: str, password: str):
    """Configures DHCP and initiates a reboot via curl."""
    dhcp_xml = '<?xml version="1.0" encoding="UTF-8"?><IPAddress version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema"><ipVersion>dual</ipVersion><addressingType>dynamic</addressingType></IPAddress>'
    cmd_dhcp = [
        "curl", "-s", "--digest", "-u", f"admin:{password}",
        "-X", "PUT", "-H", "Content-Type: application/xml",
        "-d", dhcp_xml,
        f"{target_url}/ISAPI/System/Network/interfaces/1/ipAddress"
    ]
    subprocess.run(cmd_dhcp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

    cmd_reboot = [
        "curl", "-s", "--digest", "-u", f"admin:{password}",
        "-X", "PUT",
        f"{target_url}/ISAPI/System/reboot"
    ]
    subprocess.run(cmd_reboot, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)


def provision_single_camera(mac: str, target_ip: str, password: str) -> bool:
    """Orchestrates L2 provisioning & DHCP allocation for one camera."""
    mac_upper = mac.upper()
    comment = f"Hikvision Camera - {target_ip.split('.')[-1]}"

    print(f"\n[+] Step 1: Reserving {target_ip} for {mac_upper} in Mikrotik...")
    cmd_lease = f'/ip dhcp-server lease add address={target_ip} mac-address={mac_upper} server={DHCP_SERVER} comment="{comment}"'
    run_router_cmd(cmd_lease)

    setup_temp_bridge_nat()
    time.sleep(1.5)

    target_url = "http://172.20.0.1:8080"
    try:
        print(f"[+] Step 2: Activating camera via ISAPI handshake with password...")
        activate_camera(target_url, password)
        print("    [OK] Camera successfully activated!")

        print("[+] Step 3: Enabling DHCP and sending reboot command...")
        set_dhcp_and_reboot(target_url, password)
        print("    [OK] DHCP enabled and reboot initiated.")

    finally:
        cleanup_temp_bridge_nat()

    print(f"[+] Waiting for camera {mac_upper} to obtain {target_ip} from DHCP...")
    for _ in range(15):
        time.sleep(2)
        leases = run_router_cmd(f'/ip/dhcp-server/lease/print where mac-address={mac_upper}')
        if "bound" in leases:
            print(f"🎉 SUCCESS! Camera {mac_upper} is bound to {target_ip}")
            print(f"👉 Web Panel: http://{target_ip}")
            return True
        sys.stdout.write(".")
        sys.stdout.flush()

    print(f"\n[!] Camera did not bind within 30s. Check physical connection or status in Mikrotik.")
    return False


def handle_nvr_attachment(camera_ip: str, camera_password: str):
    """
    Presents available NVRs from Didban, calculates free channels,
    and attaches the camera directly to the selected NVR.
    """
    nvrs = db_bridge.get_nvrs_from_didban()
    if not nvrs:
        print("[-] No NVRs found in Didban database. Skipping NVR attachment.")
        return

    print("\n" + "=" * 60)
    print("   NVR Attachment (from Didban Database)")
    print("=" * 60)

    # Inspect NVR capacity
    nvr_choices = []
    for idx, n in enumerate(nvrs, 1):
        channels = db_bridge.get_nvr_channels_info(n["ip"], n["user"], n["password"])
        next_free = db_bridge.find_next_free_channel(set(channels.keys()))
        free_count = 32 - len(channels)
        nvr_choices.append({
            "nvr": n,
            "next_free": next_free,
            "occupied_count": len(channels),
            "free_count": free_count
        })
        status_str = f"Next free CH: {next_free} ({free_count} free slots)" if next_free else "[FULL]"
        print(f"  {idx}. {n['name']} ({n['ip']}) - {status_str}")

    print("  0. Skip NVR attachment")

    try:
        sel = input(f"\nSelect target NVR [0-{len(nvrs)}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return

    if not sel or sel == "0":
        print("[*] NVR attachment skipped.")
        return

    try:
        chosen_idx = int(sel) - 1
        if chosen_idx < 0 or chosen_idx >= len(nvr_choices):
            print("[!] Invalid selection.")
            return
    except ValueError:
        print("[!] Invalid selection.")
        return

    chosen = nvr_choices[chosen_idx]
    if not chosen["next_free"]:
        print(f"[!] Target NVR {chosen['nvr']['name']} has no free channels!")
        return

    nvr = chosen["nvr"]
    target_ch = chosen["next_free"]

    # Optional camera name
    default_name = f"Camera {target_ch:02d}"
    try:
        custom_name = input(f"Enter camera name [default: {default_name}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        custom_name = default_name

    final_name = custom_name if custom_name else default_name

    print(f"\n[*] Attaching camera {camera_ip} to {nvr['name']} ({nvr['ip']}) on Channel {target_ch}...")
    success, msg = db_bridge.add_camera_to_nvr(
        nvr_ip=nvr["ip"],
        nvr_user=nvr["user"],
        nvr_password=nvr["password"],
        channel_id=target_ch,
        camera_name=final_name,
        camera_ip=camera_ip,
        camera_password=camera_password
    )

    if not success:
        print(f"[!] Failed to attach camera to NVR: {msg}")
        return

    print("    [OK] Configuration sent to NVR. Verifying connection status...")
    for attempt in range(6):
        time.sleep(3)
        online, det_status = db_bridge.verify_camera_connection_status(
            nvr["ip"], nvr["user"], nvr["password"], target_ch
        )
        if online:
            print(f"🎉 SUCCESS! Camera is ONLINE on {nvr['name']} (Channel {target_ch})!")
            return
        sys.stdout.write(f".({det_status})")
        sys.stdout.flush()

    print(f"\n[!] Camera added to NVR CH {target_ch}, but connection not confirmed yet (Status: {det_status}).")


def main():
    if os.geteuid() != 0:
        print("[!] This script requires root privileges for Layer 2 raw packet sniffing.")
        print("    Please run with: sudo ./start.sh or sudo python3 main.py")
        sys.exit(1)

    print("=" * 60)
    print("   Didban Provisioner: Hikvision Auto-Provision & NVR Onboarding")
    print("=" * 60)
    print(f"Interface:       {VLAN_INTERFACE}")
    print(f"Mikrotik Router: {ROUTER_HOST}")
    print(f"IP Pool:         {IP_POOL_NAME}")
    print(f"Camera Password: {CAMERA_PASSWORD}")
    print(f"Didban Database: {'Connected (data/monitor.db)' if db_bridge.is_didban_available() else 'Not found'}")
    print("=" * 60)

    try:
        pool_start, pool_end = get_pool_range(IP_POOL_NAME)
        print(f"[+] Pool range: {pool_start} -> {pool_end}")
    except Exception as e:
        print(f"[!] Failed to resolve pool range: {e}")
        sys.exit(1)

    cams = scan_unconfigured_cameras(VLAN_INTERFACE)

    if not cams:
        print("[-] No unconfigured cameras found on 192.168.1.64.")
        print(f"    Ensure the camera is powered on and connected to {VLAN_INTERFACE}.")
        
        # Even if no unactivated camera found, allow attaching an already active IP directly:
        try:
            direct_ans = input("\nDo you want to attach an already active camera IP to an NVR? [y/N]: ").strip().lower()
            if direct_ans in ("y", "yes"):
                active_ip = input("Enter active camera IP: ").strip()
                if active_ip:
                    handle_nvr_attachment(active_ip, CAMERA_PASSWORD)
        except (EOFError, KeyboardInterrupt):
            pass
        sys.exit(0)

    print(f"\n[+] Found {len(cams)} unconfigured camera(s):")
    plan = []
    used_ips = get_used_ips_from_leases(pool_start, pool_end)

    for idx, mac in enumerate(cams, 1):
        try:
            assigned_ip = get_next_available_ip(pool_start, pool_end, used_ips)
            used_ips.add(assigned_ip)
            plan.append((mac, str(assigned_ip)))
            print(f"  {idx}. MAC: {mac.upper()}  -->  Assigned IP: {assigned_ip}")
        except RuntimeError as e:
            print(f"  {idx}. MAC: {mac.upper()}  -->  [ERROR] {e}")
            print("[!] Not enough IPs in pool to provision all discovered cameras.")
            sys.exit(1)

    print("\n" + "-" * 60)
    try:
        ans = input("Do you want to proceed with provisioning these camera(s)? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n[*] Aborted by user.")
        sys.exit(0)
    if ans not in ("y", "yes"):
        print("[*] Aborted by user.")
        sys.exit(0)

    for mac, ip in plan:
        print(f"\n{'='*20} Provisioning {mac.upper()} {'='*20}")
        success = provision_single_camera(mac, ip, CAMERA_PASSWORD)
        if success:
            handle_nvr_attachment(ip, CAMERA_PASSWORD)

    print("\n[+] All tasks completed successfully!")


if __name__ == "__main__":
    main()
