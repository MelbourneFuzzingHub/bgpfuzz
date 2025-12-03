project_name = 'hijacking'
file_path = f'/home/chenlu/GNS3/projects/{project_name}/{project_name}.gns3'
config_path = "i1_startup-config.cfg"
capture_file_name = 'test-capture.pcap'
capture_path = f'/home/chenlu/GNS3/projects/{project_name}/project-files/captures/'

BASE_URL = "http://127.0.0.1:3080"  # Adjust if GNS3 server is not localhost
AUTH_HEADER = {
    "Authorization": "Basic YWRtaW46R0x2M2ExVXN4c24ySHJUb1BsRG5QRjQ4d2JjWTE5ZDdRdjZnV0tqUFlpWFNIUlFBaDM3QlBRNFByTDdsV0JqSQ==",
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
