# Hikvision Batch Provisioner for Linux

An automated CLI tool to discover, activate, reserve DHCP leases on Mikrotik RouterOS, and configure network addressing for brand-new or reset Hikvision IP cameras on Linux.

---

## Features

- **Layer 2 Discovery:** Detects unconfigured Hikvision cameras resting on factory default `192.168.1.64` using ARP scanning across designated network interfaces/VLANs.
- **ISAPI Cryptographic Handshake:** Implements Hikvision's RSA-1024 / AES-128 security challenge and activation protocol without requiring the proprietary Windows SADP tool.
- **Mikrotik RouterOS Integration:** Automatically creates static DHCP lease reservations and establishes temporary bridge NAT/DNAT forwarding to route traffic to unactivated cameras.
- **Automated DHCP Switchover:** Reconfigures camera network interface to dynamic addressing (DHCP) and initiates a reboot, confirming successful IP binding.

---

## Prerequisites

- Linux operating system with raw socket capability (`sudo` or `CAP_NET_RAW`).
- Python 3.10+
- [uv](https://docs.astral.sh/uv/) (recommended) or standard Python `venv` + `pip`.
- Network access to a Mikrotik router via SSH key authentication.
- Network interface or VLAN trunk configured on the host connected to the cameras.

---

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/hik-provisioner.git
   cd hik-provisioner
   ```

2. **Configure environment settings:**
   Copy the example environment configuration and edit it to match your network:
   ```bash
   cp .env.example .env
   nano .env
   ```

   **Configuration parameters:**
   - `VLAN_INTERFACE`: Host interface/VLAN where cameras are connected (e.g. `eno1.400`, `eth0`).
   - `ROUTER_HOST`: Mikrotik router hostname or IP (or SSH alias in `~/.ssh/config`).
   - `ROUTER_USER`: SSH username for Mikrotik (leave empty if configured in `~/.ssh/config`).
   - `DHCP_SERVER_NAME`: Mikrotik DHCP server name for camera reservations (e.g. `dhcp1`).
   - `CAMERA_PASSWORD`: New admin password to assign to the cameras upon activation.
   - `IP_POOL_START`: Starting IP for auto-assigning static DHCP reservations.

3. **Install Dependencies:**
   Install dependencies and setup the virtual environment via `uv`:
   ```bash
   uv sync
   ```

---

## Usage

Run the provisioner using the runner script:
```bash
./run.sh
```

Or run directly with Python under `sudo`:
```bash
sudo python3 main.py
```

### Workflow

1. The script broadcasts ARP requests for `192.168.1.64` on the specified interface.
2. Discovered MAC addresses are matched against existing Mikrotik DHCP leases to calculate the next free IP addresses.
3. The script presents a provisioning plan and requests confirmation.
4. Upon approval:
   - Sets static DHCP lease on Mikrotik.
   - Creates temporary NAT routing to interface with `192.168.1.64`.
   - Executes ISAPI RSA/AES key exchange and sets the activation password.
   - Instructs the camera to switch to DHCP and reboot.
   - Tears down temporary NAT rules and monitors Mikrotik leases until the camera is bound.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
