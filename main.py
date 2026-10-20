#!/usr/bin/env python3
"""
Hikvision Interactive Batch Provisioner for Linux
Discovers unactivated cameras (192.168.1.64) via L2 ARP / SADP,
reserves DHCP IP on Mikrotik, activates via RSA/AES ISAPI handshake,
and sets addressing to DHCP.
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
    print("Please run: sudo pacman -S python-scapy python-pycryptodome")
    sys.exit(1)


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
ROUTER_HOST = CFG.get("ROUTER_HOST", "router.local")
ROUTER_USER = CFG.get("ROUTER_USER", "")
DHCP_SERVER = CFG.get("DHCP_SERVER_NAME", "dhcp1")
CAMERA_PASSWORD = CFG.get("CAMERA_PASSWORD", "ChangeMe123!")
IP_POOL_NAME = CFG.get("IP_POOL_NAME", "")


def run_router_cmd(command: str) -> str:
    """Executes a command on the Mikrotik router via SSH."""
    ssh_target = f"{ROUTER_USER}@{ROUTER_HOST}" if ROUTER_USER else ROUTER_HOST
    # If invoked via sudo, detect the original invoking user to preserve SSH key access
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
        raise ValueError("IP_POOL_NAME is not set in .env. Please specify the pool name.")

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
    return used


def get_next_available_ip(start_ip: ipaddress.IPv4Address, end_ip: ipaddress.IPv4Address, used_ips: set[ipaddress.IPv4Address]) -> ipaddress.IPv4Address:
    """Finds the next unused IP in the pool range, or raises RuntimeError if full."""
    curr_int = int(start_ip)
    max_int = int(end_ip)

    while curr_int <= max_int:
        candidate = ipaddress.IPv4Address(curr_int)
        if candidate not in used_ips:
            return candidate
        curr_int += 1

    raise RuntimeError(f"IP Pool exhausted! No available IPs between {start_ip} and {end_ip}.")


def setup_temp_bridge_nat():
    """Sets up temporary IP & DNAT on Mikrotik so Linux host can access 192.168.1.64 via port 8080."""
    print("[*] Setting up temporary routing/NAT on Mikrotik...")
    cmd = """
/ip address add address=192.168.1.250/24 interface=bridge comment="Temp-Provision";
/ip firewall nat add chain=srcnat dst-address=192.168.1.64 action=masquerade comment="Temp-Provision";
/ip firewall nat add chain=dstnat dst-address=172.20.0.1 protocol=tcp dst-port=8080 action=dst-nat to-addresses=192.168.1.64 to-ports=80 comment="Temp-Provision";
"""
    run_router_cmd(cmd)


def cleanup_temp_bridge_nat():
    """Removes temporary NAT rules on Mikrotik."""
    print("[*] Cleaning up temporary routing/NAT from Mikrotik...")
    cmd = """
/ip address remove [find comment="Temp-Provision"];
/ip firewall nat remove [find comment="Temp-Provision"];
"""
    try:
        run_router_cmd(cmd)
    except Exception:
        pass


def activate_camera(target_url: str, password: str):
    """Executes the Hikvision ISAPI RSA/AES activation handshake."""
    # 1. Generate RSA Key
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    pub_numbers = key.public_key().public_numbers()
    modulus_hex = format(pub_numbers.n, "x")
    if len(modulus_hex) % 2 != 0:
        modulus_hex = "0" + modulus_hex
    pub_key_b64 = base64.b64encode(modulus_hex.encode("utf-8")).decode("utf-8")

    # 2. Request Challenge
    challenge_xml = f'<PublicKey version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema"><key>{pub_key_b64}</key></PublicKey>'
    req = urllib.request.Request(
        f"{target_url}/ISAPI/Security/challenge",
        data=challenge_xml.encode("utf-8"),
        headers={"Content-Type": "application/xml"},
        method="POST"
    )

    with urllib.request.urlopen(req, timeout=6) as resp:
        body = resp.read().decode("utf-8")

    m = re.search(r"<key>(.*?)</key>", body)
    if not m:
        raise ValueError("Invalid challenge response from camera")

    dev_key_b64 = m.group(1)
    dev_key_hex = base64.b64decode(dev_key_b64).decode("utf-8")
    encrypted_bytes = bytes.fromhex(dev_key_hex)

    decrypted_rand = key.decrypt(encrypted_bytes, padding.PKCS1v15()).decode("utf-8")
    rand_prefix = decrypted_rand[:16]

    if len(decrypted_rand) == 64:
        aes_key = bytes.fromhex(decrypted_rand[32:])
    else:
        aes_key = bytes.fromhex(decrypted_rand) if len(decrypted_rand) == 32 and all(c in "0123456789abcdefABCDEF" for c in decrypted_rand) else decrypted_rand[:16].encode("utf-8")

    # Prepare payload: 16-byte random prefix + password (padded to 16-byte block with nulls)
    pwd_bytes = password.encode("utf-8")
    if len(pwd_bytes) < 16:
        pwd_bytes = pwd_bytes + b"\x00" * (16 - len(pwd_bytes))
    elif len(pwd_bytes) % 16 != 0:
        pwd_bytes = pwd_bytes + b"\x00" * (16 - (len(pwd_bytes) % 16))

    payload = rand_prefix.encode("utf-8") + pwd_bytes

    # AES-128 in ECB mode
    cipher = AES.new(aes_key, AES.MODE_ECB)
    enc = cipher.encrypt(payload)

    enc_hex = enc.hex()
    enc_b64 = base64.b64encode(enc_hex.encode("utf-8")).decode("utf-8")

    # 3. Send ActivateInfo
    activate_xml = f'<?xml version="1.0" encoding="UTF-8"?><ActivateInfo version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema"><password>{enc_b64}</password></ActivateInfo>'
    req_act = urllib.request.Request(
        f"{target_url}/ISAPI/System/activate",
        data=activate_xml.encode("utf-8"),
        headers={"Content-Type": "application/xml"},
        method="PUT"
    )

    with urllib.request.urlopen(req_act, timeout=6) as resp:
        return resp.read().decode("utf-8")


def set_dhcp_and_reboot(target_url: str, password: str):
    """Enables DHCP and reboots the camera via Digest-authenticated curl."""
    # Use curl for reliable digest authentication
    dhcp_xml = '<?xml version="1.0" encoding="UTF-8"?><IPAddress version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema"><ipVersion>dual</ipVersion><addressingType>dynamic</addressingType></IPAddress>'
    cmd_dhcp = [
        "curl", "-s", "--digest", "-u", f"admin:{password}",
        "-X", "PUT", "-H", "Content-Type: application/xml",
        "-d", dhcp_xml,
        f"{target_url}/ISAPI/System/Network/interfaces/1/ipAddress"
    ]
    subprocess.run(cmd_dhcp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

    # Reboot command
    cmd_reboot = [
        "curl", "-s", "--digest", "-u", f"admin:{password}",
        "-X", "PUT",
        f"{target_url}/ISAPI/System/reboot"
    ]
    subprocess.run(cmd_reboot, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)


def provision_single_camera(mac: str, target_ip: str, password: str):
    """Orchestrates provisioning for one camera."""
    mac_upper = mac.upper()
    comment = f"Hikvision Camera - {target_ip.split('.')[-1]}"

    # Step 1: Add reservation in Mikrotik
    print(f"\n[+] Step 1: Reserving {target_ip} for {mac_upper} in Mikrotik...")
    cmd_lease = f'/ip dhcp-server lease add address={target_ip} mac-address={mac_upper} server={DHCP_SERVER} comment="{comment}"'
    run_router_cmd(cmd_lease)

    # Step 2: Temporary NAT
    setup_temp_bridge_nat()
    time.sleep(1.5)

    target_url = "http://172.20.0.1:8080"
    try:
        # Step 3: Activate
        print(f"[+] Step 2: Activating camera via ISAPI handshake with password...")
        activate_camera(target_url, password)
        print("    [OK] Camera successfully activated!")

        # Step 4: Set DHCP and Reboot
        print("[+] Step 3: Enabling DHCP and sending reboot command...")
        set_dhcp_and_reboot(target_url, password)
        print("    [OK] DHCP enabled and reboot initiated.")

    finally:
        # Step 5: Always cleanup NAT
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


def main():
    if os.geteuid() != 0:
        print("[!] This script requires root privileges for Layer 2 raw packet sniffing.")
        print("    Please run with: sudo ./provision.py")
        sys.exit(1)

    print("=" * 60)
    print("   Hikvision Interactive Batch Provisioner (Linux)")
    print("=" * 60)
    print(f"Interface:       {VLAN_INTERFACE}")
    print(f"Mikrotik Router: {ROUTER_HOST}")
    print(f"IP Pool:         {IP_POOL_NAME}")
    print(f"Target Password: {CAMERA_PASSWORD}")
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
        provision_single_camera(mac, ip, CAMERA_PASSWORD)

    print("\n[+] All provisioning tasks completed!")


if __name__ == "__main__":
    main()
