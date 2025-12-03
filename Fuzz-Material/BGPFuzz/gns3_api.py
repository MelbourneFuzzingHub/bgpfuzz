import requests
import time
import json
import re
import config
from config import AUTH_HEADER, BASE_URL

def get_project_and_links(file_path):
    # Load the JSON data
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None, None, None, None, None
    except json.JSONDecodeError:
        print(f"Error: Failed to decode JSON from {file_path}")
        return None, None, None, None, None

    # Extract project_id
    project_id = data.get('project_id')
    if not project_id:
        print("Error: 'project_id' field not found in the JSON file.")
        return None, None, None, None, None

    # Extract nodes and links from topology
    topology = data.get('topology', {})
    nodes = topology.get('nodes', [])
    links = topology.get('links', [])

    if not nodes:
        print("Error: No nodes found in the 'topology' field of the JSON file.")
        return project_id, None, None, None, None

    # Create a mapping from node_id to node_name
    node_id_to_name = {node['node_id']: node['name'] for node in nodes if 'node_id' in node and 'name' in node}

    # Display nodes
    print(f"Project ID: {project_id}")
    print("Available Nodes:")
    node_choices = {node['name']: node['node_id'] for node in nodes if 'node_id' in node and 'name' in node}
    port_choices = {node['name']: node['console'] for node in nodes if 'node_id' in node and 'name' in node}
    global all_ports
    all_ports = port_choices

    if not node_choices:
        print("No valid nodes found with both 'node_id' and 'name'.")
        return project_id, None, None, None, None

    print("\nChoose a node by its name from the list:")
    for name in node_choices.keys():
        print(f"  - {name}")

    chosen_name = input("Enter the name of the node you want to select: ").strip()
    node_id = node_choices.get(chosen_name)
    telnet_port = port_choices.get(chosen_name)
    print("chosen_name"+chosen_name)
    number_node = chosen_name[1:]
    config_path = re.sub(r'i\d+_', f'i{number_node}_', config.config_path)


    if not node_id:
        print("Invalid choice. Node name not found.")
        return project_id, None, None, None, config_path
    if not telnet_port:
        print("Invalid choice. Port not found.")
        return project_id, None, None, None, config_path

    # Filter and display links for the chosen node
    print("\nAvailable Links for the selected node:")
    filtered_links = [
        link for link in links
        if any(node['node_id'] == node_id for node in link['nodes'])
    ]

    if not filtered_links:
        print("No links found for the selected node.")
        return project_id, node_id, None, telnet_port, config_path

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
        return project_id, node_id, None, telnet_port, config_path

    return project_id, node_id, link_id, telnet_port, config_path

def reload_all_nodes(project_id):
    url = f"{BASE_URL}/v2/projects/{project_id}/nodes/reload"
    response = requests.post(url, headers=AUTH_HEADER)
    if response.ok:
        print("[+] All nodes reloaded.")
    else:
        print(f"[!] Reload failed: {response.status_code}, {response.text}")

def get_config_file(project_id, node_id, config_path):
    url = f"{BASE_URL}/v2/projects/{project_id}/nodes/{node_id}/files/configs/{config_path}"
    print(url)
    response = requests.get(url, headers=AUTH_HEADER)
    if response.ok:
        return response.text
    print("[!] Failed to get config.")
    return None

def upload_config_file(project_id, node_id, config_path, config_data):
    url = f"{BASE_URL}/v2/projects/{project_id}/nodes/{node_id}/files/configs/{config_path}"
    headers = AUTH_HEADER.copy()
    headers["Content-Type"] = "application/octet-stream"
    response = requests.post(url, headers=headers, data=config_data)
    if response.status_code == 201:
        print("[+] Config uploaded.")
    else:
        print(f"[!] Upload failed: {response.status_code}, {response.text}")

def stop_node(project_id, node_id):
    url = f"{BASE_URL}/v2/projects/{project_id}/nodes/{node_id}/stop"
    requests.post(url, headers=AUTH_HEADER)

def start_node(project_id, node_id):
    url = f"{BASE_URL}/v2/projects/{project_id}/nodes/{node_id}/start"
    requests.post(url, headers=AUTH_HEADER)

def upload_config_with_restart(project_id, node_id, config_path, config_data):
    stop_node(project_id, node_id)
    time.sleep(2)
    upload_config_file(project_id, node_id, config_path, config_data)
    time.sleep(1)
    start_node(project_id, node_id)

def start_capture(project_id, link_id, capture_file_name):
    url = f"{BASE_URL}/v2/projects/{project_id}/links/{link_id}/start_capture"
    data = {
        "capture_file_name": capture_file_name,
        "data_link_type": "DLT_EN10MB"
    }
    response = requests.post(url, headers=AUTH_HEADER, json=data)
    if response.status_code == 201:
        print("[+] Capture started.")
    else:
        print(f"[!] Capture error: {response.status_code}, {response.text}")

def stop_capture(project_id, link_id, capture_file_name):
    url = f"{BASE_URL}/v2/projects/{project_id}/links/{link_id}/stop_capture"
    data = {
        "capture_file_name": capture_file_name,
        "data_link_type": "DLT_EN10MB"
    }
    response = requests.post(url, headers=AUTH_HEADER, json=data)
    if response.status_code == 201:
        print("[+] Capture started.")
    else:
        print(f"[!] Capture error: {response.status_code}, {response.text}")