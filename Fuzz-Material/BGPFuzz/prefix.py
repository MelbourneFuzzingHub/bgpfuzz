import subprocess
import re
import ipaddress
import tempfile
import os
import pandas as pd


log_path = "bgp_output.log"

def get_vm_path():
    result = subprocess.run(["vmrun", "list"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if line.strip().endswith(".vmx"):
            return line.strip()
    return None

def get_vm_ip(vmx_path):
    result = subprocess.run(["vmrun", "getGuestIPAddress", vmx_path], capture_output=True, text=True)
    return result.stdout.strip()

def run_expect_telnet(vm_ip, port, log_path):
    print("we are after 10000")
    expect_script = f"""
#!/usr/bin/expect -f
set timeout 10
set host "{vm_ip}"
set port "{port}"

log_file -noappend {log_path}

spawn telnet $host $port

# Wait briefly for router to settle
after 2000

# Try sending Enter multiple times until we see a shell prompt
set tries 15
while {{ $tries > 0 }} {{
    send "\\r"
    expect {{
        -re {{[>#]}} {{ break }}
        timeout {{ incr tries -1 }}
    }}
}}



# Disable pagination to get full output
expect -re {{[>#]}}
send "terminal length 0\\r"

# Send 'show ip bgp' command

expect -re {{[>#]}}
send "show ip bgp\\r"
expect -re {{[>#]}}
send "show ip bgp\\r"
expect -re {{[>#]}}
send "show ip bgp\\r"
expect -re {{[>#]}}
send "show ip int br\\r"
expect -re {{[>#]}}
send "show ip route\\r"

# Wait for prompt again to ensure output completes
expect -re {{[>#]}}
send "exit\\r"
"""

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".exp") as f:
        f.write(expect_script)
        script_path = f.name

    os.chmod(script_path, 0o755)
    subprocess.run(["expect", script_path])
    os.remove(script_path)

def extract_prefixes(log_path):
    prefixes = set()

    # Match entries like: *> 10.0.1.0/30 OR *> 208.65.153.0 (no mask)
    bgp_line_pattern = re.compile(
        r'^\s*\*>?\s+(\d{1,3}(?:\.\d{1,3}){3})(/\d{1,2})?', re.IGNORECASE
    )

    with open(log_path, "r") as f:
        for line in f:
            match = bgp_line_pattern.match(line)
            if match:
                ip = match.group(1)
                mask = match.group(2)
                if mask:
                    prefix = f"{ip}{mask}"
                else:
                    prefix = f"{ip}/24"  # Default to /24 if no mask

                try:
                    ip_net = ipaddress.IPv4Network(prefix, strict=False)
                    if ip_net.network_address == ipaddress.IPv4Address("0.0.0.0"):
                        continue
                    prefixes.add(str(ip_net))
                except Exception as e:
                    print(f"Warning: Skipping invalid prefix {prefix} ({e})")

    return sorted(prefixes)

def extract_static_and_loopbacks(log_path):
    static_routes = []
    loopback_routes = []
    all_prefixes = set()

    # Match routes like:
    # S        12.12.12.0/24 is directly connected, Null0
    # C        12.12.12.12/32 is directly connected, Loopback0
    route_pattern = re.compile(
        r'^(S|C)\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s+is directly connected, (\S+)', re.IGNORECASE)

    with open(log_path, "r") as f:
        for line in f:
            match = route_pattern.match(line.strip())
            if match:
                route_type = match.group(1)
                prefix = match.group(2)
                iface = match.group(3)
                try:
                    ip_net = ipaddress.IPv4Network(prefix, strict=False)
                except Exception as e:
                    print(f"Warning: Skipping invalid prefix {prefix} ({e})")
                    continue

                if iface.lower() == "null0" and route_type == "S":
                    print("static match")
                    static_routes.append({"prefix": prefix, "interface": iface})
                    all_prefixes.add(str(ip_net))
                elif iface.lower().startswith("loopback"):
                    print("loopback match")
                    loopback_routes.append({"prefix": prefix, "interface": iface})
                    all_prefixes.add(str(ip_net))

    return sorted(all_prefixes)


def get_prefix(telnet_port):
    # Note: we didn't check if it is GNS3 VM

    vmx_path = get_vm_path()
    if not vmx_path:
        print("No running VMs found.")
        return
    print(f"[+] Found VM: {vmx_path}")

    vm_ip = get_vm_ip(vmx_path)
    if not vm_ip:
        print("[-] Failed to get VM IP address.")
        return
    print(f"[+] VM IP: {vm_ip}")

    print("[*] Launching Telnet and sending 'show ip bgp'...")
    run_expect_telnet(vm_ip, telnet_port, log_path)

    print("[*] Extracting BGP prefixes from log...")
    prefixes = extract_prefixes(log_path)

    if prefixes:
        print("[+] Prefixes found in routing table:")
        for pfx in prefixes:
            print(f"  - {pfx}")
        return prefixes
    else:
        print("[-] No BGP prefixes found.")
        return []


def get_subnet(telnet_port):
    # Note: we didn't check if it is GNS3 VM

    vmx_path = get_vm_path()
    if not vmx_path:
        print("No running VMs found.")
        return
    print(f"[+] Found VM: {vmx_path}")

    vm_ip = get_vm_ip(vmx_path)
    if not vm_ip:
        print("[-] Failed to get VM IP address.")
        return
    print(f"[+] VM IP: {vm_ip}")

    print("[*] Launching Telnet and sending 'show ip bgp'...")
    run_expect_telnet(vm_ip, telnet_port, log_path)

    print("[*] Extracting BGP prefixes from log...")
    prefixes = extract_static_and_loopbacks(log_path)

    if prefixes:
        print("[+] Prefixes found for subnet:")
        for pfx in prefixes:
            print(f"  - {pfx}")
        return prefixes
    else:
        print("[-] No subnet prefixes found.")
        return []


def get_ios_log():
    # Note: we expect get_subnet run before this func so the log file already exist

    print("[*] Extracting network incidents from log...")
    with open(log_path, "r") as result:
        return result.readlines()
    

all_pfx = extract_static_and_loopbacks(log_path=log_path)
for _ in all_pfx:
    print(ipaddress.IPv4Network(_).network_address)

# prefixes = extract_prefixes("bgp_output.log")
# print(prefixes)