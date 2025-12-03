import json
import requests
import random
from typing import Tuple, List, Callable, Set, Any
from fuzzingbook.Fuzzer import Fuzzer
import subprocess
import re
from concurrent.futures import ThreadPoolExecutor
import time
import pyshark

# Global Config Setting
project_name = 'cmp-multitopo'
file_path = '/home/test/GNS3/projects/' + project_name + '/' + project_name + '.gns3'
capture_file_name = 'test-capture.pcap'

# Path to the pcap file
capture_file_path = "/home/test/GNS3/projects/" + project_name + "/project-files/captures/" + capture_file_name

# Error pattern to search for
error_pattern = re.compile(r"BGP", re.IGNORECASE)

# Config name to update
config_path = "i1_startup-config.cfg"

# Base configuration
BASE_URL = "http://127.0.0.1:3080"  # Adjust if GNS3 server is not localhost
AUTH_HEADER = {
    "Authorization": "Basic YWRtaW46bldCTnI5TWk3RVRqeGFocUxmQXpNTFVwV3daN0ZJbGxicnViR01LVkVVMlpiZldoeG4wajFycGRKZ0JOdVF4Yw==",
    "User-Agent": "GNS3 QT Client v2.2.49",
    "Content-Type": "application/json"
}

print("capture_file_path is " + capture_file_path)

network_config_grammar = {
    "<start>": ["<config_statements>"],
    "<config_statements>": [
        "<config_statement>",
        "<config_statements>\n<config_statement>"
    ],
    "<config_statement>": [
        "<comment>",
        "<command>",
        "<block>",
        "<interface_config>",
        "<router_config>",
        "<line_config>"
    ],
    "<comment>": ["!"],
    "<command>": [
        "upgrade fpd auto",
        "version <version_number>",
        "service timestamps <timestamps_type> datetime msec",
        "no service password-encryption",
        "ip cef",
        "no ip domain lookup",
        "no ipv6 cef",
        "ip tcp synwait-time <time_value>",
        "no ip http server",
        "no ip http secure-server",
        "no cdp log mismatch duplex",
        "redundancy",
        "control-plane"
    ],
    "<block>": [
        "hostname <hostname>",
        "boot-start-marker",
        "boot-end-marker",
        "router bgp <asn>\n<bgp_config>",
        "mgcp profile default",
        "gatekeeper shutdown"
    ],
    "<interface_config>": [
        "interface <interface_name>\n <ip_address_command>\n <duplex_command>\n <speed_command>"
    ],
    "<router_config>": [
        "router bgp <asn>\n <bgp_settings>"
    ],
    "<line_config>": [
        "line <line_type> <line_range>\n <line_settings>"
    ],
    "<timestamps_type>": ["debug", "log"],
    "<version_number>": ["15.3"],
    "<hostname>": ["R1"],
    "<asn>": ["<number>"],
    "<number>": ["<digit>", "<digit><number>"],
    "<digit>": ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
    "<bgp_config>": [
        "bgp router-id <router_id>",
        "bgp log-neighbor-changes",
        "network <network_address> mask <subnet_mask>",
        "neighbor <neighbor_ip> remote-as <remote_as>",
        "neighbor <neighbor_ip> maximum-prefix <maximum_prefix> <threshold>"
    ],
    "<bgp_settings>": [
        "bgp router-id <router_id>",
        "bgp log-neighbor-changes",
        "network <network_address> mask <subnet_mask>",
        "neighbor <neighbor_ip> remote-as <remote_as>"
    ],
    "<interface_name>": ["FastEthernet0/0"],
    "<ip_address_command>": ["ip address <ip_address> <subnet_mask>"],
    "<duplex_command>": ["duplex auto"],
    "<speed_command>": ["speed auto"],
    "<line_type>": ["con", "aux", "vty"],
    "<line_range>": ["0", "0 4"],
    "<line_settings>": [
        "exec-timeout <minutes> <seconds>",
        "privilege level <level>",
        "logging synchronous",
        "stopbits <stopbits_value>",
        "login",
        "transport input all"
    ],
    "<router_id>": ["<ip_address>"],
    "<ip_address>": ["<octet>.<octet>.<octet>.<octet>"],
    "<octet>": [
        "<digit1>",
        "<digit2>",
        "<digit3>"
    ],
    "<digit1>": [str(i) for i in range(0, 10)],  # 0–9
    "<digit2>": [str(i) for i in range(10, 100)],  # 10–99
    "<digit3>": [str(i) for i in range(100, 256)],  # 100–255
    "<network_address>": ["<ip_address>"],
    "<subnet_mask>": ["<octet>.<octet>.<octet>.<octet>"],
    "<neighbor_ip>": ["<ip_address>"],
    "<remote_as>": ["<asn>"],
    "<minutes>": ["<number>"],
    "<seconds>": ["<number>"],
    "<level>": ["15"],
    "<stopbits_value>": ["1"],
    "<maximum_prefix>": ["<number>"],
    "<threshold>": ["<number>"],
    "<time_value>": ["<number>"]
}

def get_project_and_links(file_path):
    # Load the JSON data
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None, None, None
    except json.JSONDecodeError:
        print(f"Error: Failed to decode JSON from {file_path}")
        return None, None, None

    # Extract project_id
    project_id = data.get('project_id')
    if not project_id:
        print("Error: 'project_id' field not found in the JSON file.")
        return None, None, None

    # Extract nodes and links from topology
    topology = data.get('topology', {})
    nodes = topology.get('nodes', [])
    links = topology.get('links', [])

    if not nodes:
        print("Error: No nodes found in the 'topology' field of the JSON file.")
        return project_id, None, None

    # Create a mapping from node_id to node_name
    node_id_to_name = {node['node_id']: node['name'] for node in nodes if 'node_id' in node and 'name' in node}

    # Display nodes
    print(f"Project ID: {project_id}")
    print("Available Nodes:")
    node_choices = {node['name']: node['node_id'] for node in nodes if 'node_id' in node and 'name' in node}
    
    if not node_choices:
        print("No valid nodes found with both 'node_id' and 'name'.")
        return project_id, None, None

    print("\nChoose a node by its name from the list:")
    for name in node_choices.keys():
        print(f"  - {name}")

    chosen_name = input("Enter the name of the node you want to select: ").strip()
    node_id = node_choices.get(chosen_name)

    if not node_id:
        print("Invalid choice. Node name not found.")
        return project_id, None, None

    # Filter and display links for the chosen node
    print("\nAvailable Links for the selected node:")
    filtered_links = [
        link for link in links
        if any(node['node_id'] == node_id for node in link['nodes'])
    ]

    if not filtered_links:
        print("No links found for the selected node.")
        return project_id, node_id, None

    link_choices = {}
    for i, link in enumerate(filtered_links, start=1):
        # Find nodes connected to the current node via this link
        connected_nodes = [node for node in link['nodes'] if node['node_id'] != node_id]
        connected_node_names = [node_id_to_name.get(node['node_id'], "Unknown") for node in connected_nodes]
        link_name = f"Link {i} (Connected to: {', '.join(connected_node_names)})"
        link_choices[link_name] = link['link_id']
        print(f"  {i}. {link_name}")

    chosen_link = input("Enter the number of the link you want to listen to: ").strip()

    try:
        chosen_link_name = list(link_choices.keys())[int(chosen_link) - 1]
        link_id = link_choices[chosen_link_name]
    except (IndexError, ValueError):
        print("Invalid choice. Link not found.")
        return project_id, node_id, None

    return project_id, node_id, link_id

def start_capture(project_id, link_id, capture_file_name):
    """Start packet capture on a specified link in the given project."""
    url = f"{BASE_URL}/v2/projects/{project_id}/links/{link_id}/start_capture"
    data = {
        "capture_file_name": capture_file_name,  # Specify the capture file name
        "data_link_type": "DLT_EN10MB"  # Ethernet data link type
    }

    try:
        response = requests.post(url, headers=AUTH_HEADER, json=data)

        if response.status_code == 201:
            print("Capture started successfully.")
            print("Capture details:", response.json())
        else:
            print(f"Failed to start capture. Status code: {response.status_code}")
            print("Error details:", response.text)
    except requests.exceptions.RequestException as e:
        print(f"Error during capture request: {e}")
    time.sleep(10)

def display_error_ansi(message):
    """Print an error message in red using ANSI escape codes."""
    print(f"\033[91m{message}\033[0m")


def scan_pcap_file(file_path):
    print(f"Scanning {file_path} for BGP UPDATE packets...")

    try:
        capture = pyshark.FileCapture(file_path, display_filter="bgp.type == 3")

        for packet in capture:
            print("\033[94m[+] BGP UPDATE packet found!\033[0m")
            print(packet)
        
        capture.close()

    except Exception as e:
        display_error_ansi(f"An error occurred while scanning: {e}")

# Function to retrieve a configuration file
def get_config_file(node_id, config_path):
    """Retrieve a configuration file from the node."""
    url = f"{BASE_URL}/v2/projects/{project_id}/nodes/{node_id}/files/configs/{config_path}"
    response = requests.get(url, headers=AUTH_HEADER)
    if response.status_code == 200:
        print("Configuration file retrieved successfully.")
        return response.text
    else:
        print(f"Failed to retrieve configuration file. Status code: {response.status_code}")
        return None

def stop_node(project_id, node_id):
    url = f"{BASE_URL}/v2/projects/{project_id}/nodes/{node_id}/stop"
    response = requests.post(url, headers=AUTH_HEADER)
    if response.ok:
        print(f"Node {node_id} stopped successfully.")
    else:
        print(f"Failed to stop node. Status: {response.status_code}, {response.text}")

def start_node(project_id, node_id):
    url = f"{BASE_URL}/v2/projects/{project_id}/nodes/{node_id}/start"
    response = requests.post(url, headers=AUTH_HEADER)
    if response.ok:
        print(f"Node {node_id} started successfully.")
    else:
        print(f"Failed to start node. Status: {response.status_code}, {response.text}")


# Function to upload a configuration file
def upload_config_file(project_id, node_id, config_path, config_data):
    url = f"{BASE_URL}/v2/projects/{project_id}/nodes/{node_id}/files/configs/{config_path}"
    headers = AUTH_HEADER.copy()
    headers["Content-Type"] = "application/octet-stream"

    response = requests.post(url, headers=headers, data=config_data)
    if response.status_code == 201:
        print("Configuration file uploaded successfully.")
    else:
        print(f"Failed to upload config. Status: {response.status_code}, Response: {response.text}")

def upload_config_with_restart(project_id, node_id, config_path, config_data):
    print(f"[+] Stopping node {node_id}...")
    stop_node(project_id, node_id)
    time.sleep(2)

    print("[+] Uploading configuration...")
    upload_config_file(project_id, node_id, config_path, config_data)
    time.sleep(1)

    print(f"[+] Starting node {node_id}...")
    start_node(project_id, node_id)

import re
from typing import Tuple

# Regex to match 'neighbor <ip> maximum-prefix <num> <threshold>'
max_prefix_pattern = re.compile(
    r'(neighbor\s+\d{1,3}(?:\.\d{1,3}){3}\s+maximum-prefix\s+)(\d+)(\s+\d+)', re.IGNORECASE
)

def force_max_prefix_one(config: str) -> Tuple[str, str]:
    """
    Finds 'maximum-prefix' lines and replaces the first numeric value with '1'.
    Returns the modified config and the specific change.
    """
    def replacer(match):
        before = match.group(0)
        after = match.group(1) + "1" + match.group(3)
        return after, f"{before} -> {after}"

    mutated_part = None

    def replacement_func(m):
        nonlocal mutated_part
        new_line, mutated_part = replacer(m)
        return new_line

    mutated_config = max_prefix_pattern.sub(replacement_func, config)

    return mutated_config, mutated_part

class MaxPrefixFuzzer(Fuzzer):
    def __init__(self, seed: list) -> None:
        self.seed = seed
        self.reset()

    def reset(self) -> None:
        self.population = self.seed
        self.seed_index = 0

    def mutate(self, inp: str) -> Tuple[str, str]:
        return force_max_prefix_one(inp)

    def fuzz(self) -> Tuple[str, str]:
        if self.seed_index < len(self.seed):
            self.inp = self.seed[self.seed_index]
            self.seed_index += 1
        else:
            self.inp, _ = self.mutate(random.choice(self.population))
        return self.inp, "max-prefix forced to 1"


# Get the project ID, selected node, and selected link
project_id, node_id, link_id = get_project_and_links(file_path)

if project_id and node_id and link_id:
    print(f"\nSelected Project ID: {project_id}")
    print(f"Selected Node ID: {node_id}")
    print(f"Selected Link ID: {link_id}")

    

    # Retrieve the original configuration file
    original_config = get_config_file(node_id=node_id, config_path=config_path)

    if original_config:
        # Initialize the fuzzer with the original configuration as the seed
        fuzzer = MaxPrefixFuzzer(seed=[original_config])

        # Generate and upload 15 mutated configurations
        for i in range(1):
            mutated_config, mutated_part = fuzzer.fuzz()
            print(f"\nMutation {i + 1}: Mutated Part -> {mutated_part}\n")
            upload_config_with_restart(project_id=project_id, node_id=node_id, config_path=config_path, config_data=mutated_config)
            # capture_file_name = input("Enter the capture file name (e.g., capture.pcap): ").strip()
            start_capture(project_id, link_id, capture_file_name)
            time.sleep(50)
            scan_pcap_file(capture_file_path)
            print("Scan complete.\n")
