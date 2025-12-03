import ipaddress
import pyshark
from prefix import get_prefix, get_ios_log

def oracle_duplicate_prefix(telnet_port):
    raw = get_prefix(telnet_port)
    prefixes = [ipaddress.IPv4Network(p) for p in raw if p]
    suspicious = []
    for i in range(len(prefixes)):
        for j in range(len(prefixes)):
            if i != j and prefixes[i].subnet_of(prefixes[j]) and prefixes[i] != prefixes[j]:
                suspicious.append((str(prefixes[j]), str(prefixes[i])))
    if suspicious:
        print("[!] Duplicate prefix pattern detected:")
        for s, sub in suspicious:
            print(f" - {sub} is a sub-prefix of {s}")
        return True, suspicious
    return False, []

def oracle_scan_ios_log():
    flag  = False
    suspicious = []
    lines = get_ios_log()
    for line in lines:
        if "Invalid input" in line:
            flag = True
            suspicious.append(line)
            display_error_ansi(line.strip())
        if "overlap" in line:
            flag = True
            suspicious.append(line)
            display_error_ansi(line.strip())
    return flag, suspicious

def oracle_scan_pcap_file(file_path):
    print(f"Scanning {file_path} for BGP NOTIFICATION packets...")
    flag = False
    suspicious = []

    try:
        capture = pyshark.FileCapture(file_path, display_filter="bgp.type == 3")

        for packet in capture:
            flag = True
            suspicious.append(packet)
            print("\033[94m[+] BGP NOTIFICATION packet found!\033[0m")
            print(packet)
        
        capture.close()
        print("Oracle 1: Scan complete.\n")

    except Exception as e:
        display_error_ansi(f"An error occurred while scanning: {e}")
    return flag, suspicious

def display_error_ansi(message):
    """Print an error message in red using ANSI escape codes."""
    print(f"\033[91m{message}\033[0m")