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
file_path = '/home/test/GNS3/projects/multi-router-project/multi-router-project.gns3'
capture_file_name = 'test-capture.pcap'

# Path to the pcap file
capture_file_path = "/home/test/GNS3/projects/multi-router-project/project-files/captures/" + capture_file_name

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
        mutators = [targeted_flip_mutation]
        mutator = random.choice(mutators)
        return mutator(inp)

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



