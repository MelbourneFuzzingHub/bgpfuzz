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
error_pattern = re.compile(r"error", re.IGNORECASE)

# Config name to update
config_path = "i1_startup-config.cfg"

# Base configuration
BASE_URL = "http://127.0.0.1:3080"  # Adjust if GNS3 server is not localhost
AUTH_HEADER = {
    "Authorization": "Basic YWRtaW46bldCTnI5TWk3RVRqeGFocUxmQXpNTFVwV3daN0ZJbGxicnViR01LVkVVMlpiZldoeG4wajFycGRKZ0JOdVF4Yw==",
    "User-Agent": "GNS3 QT Client v2.2.49",
    "Content-Type": "application/json"
}

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
        "neighbor <neighbor_ip> remote-as <remote_as>"
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
    "<ip_address>": ["<number>.<number>.<number>.<number>"],
    "<network_address>": ["<ip_address>"],
    "<subnet_mask>": ["<number>.<number>.<number>.<number>"],
    "<neighbor_ip>": ["<ip_address>"],
    "<remote_as>": ["<asn>"],
    "<minutes>": ["<number>"],
    "<seconds>": ["<number>"],
    "<level>": ["15"],
    "<stopbits_value>": ["1"]
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
    """Scan the .pcap file for packets containing the error pattern."""
    print(f"Scanning {file_path} for errors...")

    try:
        # Open the .pcap file for packet reading
        capture = pyshark.FileCapture(file_path)

        # Process packets sequentially
        for packet in capture:
            # Convert packet layers to a single string for searching
            packet_summary = str(packet)
            if error_pattern.search(packet_summary):
                display_error_ansi(f"Error found: ")
                print(f"{packet_summary}")

        # Properly close the capture
        capture.close()

    except Exception as e:
        print(f"An error occurred: {e}")


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

# Function to upload a configuration file
def upload_config_file(node_id, config_path, config_data):
    """Upload a configuration file to the node."""
    url = f"{BASE_URL}/v2/projects/{project_id}/nodes/{node_id}/files/configs/{config_path}"
    headers = AUTH_HEADER.copy()
    headers["Content-Type"] = "application/octet-stream"
    response = requests.post(url, headers=headers, data=config_data)
    if response.status_code == 201:
        print("Configuration file uploaded successfully.")
    else:
        print(f"Failed to upload configuration file. Status code: {response.status_code}, Response: {response.text}")

# Mutation function
def flip_random_character(s: str) -> str:
    """Returns s with a random bit flipped in a random position."""
    if s == "":
        return s
    pos = random.randint(0, len(s) - 1)
    c = s[pos]
    bit = 1 << random.randint(0, 6)
    new_c = chr(ord(c) ^ bit)
    return s[:pos] + new_c + s[pos + 1:]

# Define regex patterns for IP addresses
ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
keywords = ["ip address", "network", "neighbor"]

def flip_random_bit_in_ip(ip_str: str) -> str:
    """Flips a random bit in an IP-like string."""
    pos = random.randint(0, len(ip_str) - 1)
    c = ip_str[pos]
    bit = 1 << random.randint(0, 6)
    new_c = chr(ord(c) ^ bit)
    return ip_str[:pos] + new_c + ip_str[pos + 1:]

def mutate_bgp_attributes(line: str) -> str:
    """
    Specifically mutates BGP attributes like `router_id`, `network`, or `neighbor` details.
    """
    if "router-id" in line:
        new_router_id = ".".join(str(random.randint(1, 254)) for _ in range(4))
        line = re.sub(ip_pattern, new_router_id, line)
        print(f"Mutated router-id to {new_router_id}")
    elif "network" in line:
        new_network = ".".join(str(random.randint(1, 254)) for _ in range(4))
        new_mask = "255.255.255.0"  # Example mutation
        line = re.sub(ip_pattern, new_network, line, 1)
        line = re.sub(ip_pattern, new_mask, line, 1)
        print(f"Mutated network to {new_network} mask {new_mask}")
    elif "neighbor" in line:
        new_neighbor_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        new_remote_as = random.randint(1, 65000)
        line = re.sub(ip_pattern, new_neighbor_ip, line)
        line = re.sub(r'\b\d+\b', str(new_remote_as), line)
        print(f"Mutated neighbor to {new_neighbor_ip} remote-as {new_remote_as}")
    return line


def targeted_flip_mutation(config: str) -> Tuple[str, str]:
    """
    Performs a bit flip mutation on IP addresses in lines containing network-related keywords.
    Returns the full mutated configuration and only the mutated part.
    """
    lines = config.splitlines()
    mutated_lines = []
    mutated_part = None

    for line in lines:
        # Check if the line contains any of the specified keywords
        if any(keyword in line for keyword in keywords):
            # Search for IP addresses in the line
            ips = ip_pattern.findall(line)
            if ips:
                # Choose a random IP address from the line to mutate
                chosen_ip = random.choice(ips)
                # Mutate the chosen IP
                mutated_ip = flip_random_bit_in_ip(chosen_ip)
                # Replace the original IP with the mutated IP in the line
                line = line.replace(chosen_ip, mutated_ip, 1)
                mutated_part = f"{chosen_ip} -> {mutated_ip}"  # Store the mutated part
                print(f"Mutated IP: {chosen_ip} -> {mutated_ip}")

        mutated_lines.append(line)

    # Join the lines back into a single configuration string
    return "\n".join(mutated_lines), mutated_part

import random

# Reuse the network_config_grammar from the earlier example
# Assuming `network_config_grammar` is defined as described previously

def generate_random_ip() -> str:
    """Generate a random IP address."""
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

def generate_random_asn() -> str:
    """Generate a random Autonomous System Number (ASN)."""
    return str(random.randint(1, 65000))

def mutate_bgp_config(grammar: dict, bgp_config: str) -> str:
    """
    Mutates the BGP configuration by applying grammar-based mutations.
    """
    lines = bgp_config.splitlines()
    mutated_lines = []

    for line in lines:
        # Check if the line matches any specific rule in the grammar tree
        if "router-id" in line:
            # Replace router_id with a randomly generated IP
            new_router_id = generate_random_ip()
            line = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", new_router_id, line)
            print(f"Mutated router-id to {new_router_id}")
        elif "network" in line:
            # Replace network_address and subnet_mask
            new_network = generate_random_ip()
            new_mask = generate_random_ip()
            line = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", new_network, line, 1)
            line = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", new_mask, line, 1)
            print(f"Mutated network to {new_network} mask {new_mask}")
        elif "neighbor" in line:
            # Replace neighbor_ip and remote_as
            new_neighbor_ip = generate_random_ip()
            new_remote_as = generate_random_asn()
            line = re.sub(r"\b\d{1,3}(\.\d{1,3}){3}\b", new_neighbor_ip, line)
            line = re.sub(r"\b\d+\b", new_remote_as, line)
            print(f"Mutated neighbor to {new_neighbor_ip} remote-as {new_remote_as}")

        mutated_lines.append(line)

    return "\n".join(mutated_lines)

def targeted_flip_with_grammar(config: str, grammar: dict) -> Tuple[str, str]:
    """
    Mutates BGP configuration based on the provided grammar.
    """
    lines = config.splitlines()
    mutated_lines = []
    mutated_part = None

    in_bgp_config = False
    bgp_block = []

    for line in lines:
        # Detect the start and end of the BGP block
        if "router bgp" in line:
            in_bgp_config = True
            bgp_block.append(line)
            continue
        if in_bgp_config:
            if not line.strip() or line.startswith("!"):
                in_bgp_config = False
                # Mutate the BGP block using the grammar
                original_bgp_block = "\n".join(bgp_block)
                mutated_bgp_block = mutate_bgp_config(grammar, original_bgp_block)
                mutated_lines.extend(mutated_bgp_block.splitlines())
                mutated_part = original_bgp_block + "\n->\n" + mutated_bgp_block
                bgp_block = []
            else:
                bgp_block.append(line)
        else:
            mutated_lines.append(line)

    return "\n".join(mutated_lines), mutated_part


# Custom fuzzer class
class MyBaselineFuzzer(Fuzzer):
    """Base class for mutational fuzzing."""

    def __init__(self, seed: List[str], min_mutations: int = 2, max_mutations: int = 10) -> None:
        self.seed = seed
        self.min_mutations = min_mutations
        self.max_mutations = max_mutations
        self.reset()

    def reset(self) -> None:
        self.population = self.seed
        self.seed_index = 0

    def mutate(self, inp: str) -> Tuple[str, str]:
        return targeted_flip_with_grammar(inp, network_config_grammar)

    def create_candidate(self) -> Tuple[str, str]:
        candidate = random.choice(self.population)
        trials = random.randint(self.min_mutations, self.max_mutations)
        for _ in range(trials):
            candidate, mutated_part = self.mutate(candidate)
        return candidate, mutated_part

    def fuzz(self) -> Tuple[str, str]:
        mutated_part = ""
        if self.seed_index < len(self.seed):
            self.inp = self.seed[self.seed_index]
            self.seed_index += 1
        else:
            self.inp, mutated_part = self.create_candidate()
        return self.inp, mutated_part

# Get the project ID, selected node, and selected link
project_id, node_id, link_id = get_project_and_links(file_path)

if project_id and node_id and link_id:
    print(f"\nSelected Project ID: {project_id}")
    print(f"Selected Node ID: {node_id}")
    print(f"Selected Link ID: {link_id}")

    # capture_file_name = input("Enter the capture file name (e.g., capture.pcap): ").strip()
    start_capture(project_id, link_id, capture_file_name)

    # Retrieve the original configuration file
    original_config = get_config_file(node_id=node_id, config_path=config_path)

    if original_config:
        # Initialize the fuzzer with the original configuration as the seed
        fuzzer = MyBaselineFuzzer(seed=[original_config])

        # Generate and upload 15 mutated configurations
        for i in range(10000):
            mutated_config, mutated_part = fuzzer.fuzz()
            print(f"\nMutation {i + 1}: Mutated Part -> {mutated_part}\n")
            upload_config_file(node_id=node_id, config_path=config_path, config_data=mutated_config)
            scan_pcap_file(capture_file_path)
            print("Scan complete.\n")



