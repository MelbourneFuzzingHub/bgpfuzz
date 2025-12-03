# BGPFuzz: Automated Configuration Fuzzing of the Border Gateway Protocol

This project provides a fuzz testing framework for the BGP (Border Gateway Protocol), including setup scripts for configuring a GNS3 simulation environment and a Python-based fuzzer for protocol testing. The framework was developed by Chenlu Zhang with advice from Dr. Amirmohammad Pasdar and Dr. Thuan Pham at the University of Melbourne.

## License

![](https://i.creativecommons.org/l/by-nc-sa/4.0/88x31.png)

This work is licensed under a [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-nc-sa/4.0/).

## Prerequisites

To install system dependencies:

```bash
sudo apt install python3 python3-pip pipx \
python3-pyqt5 python3-pyqt5.qtwebsockets python3-pyqt5.qtsvg \
qemu-kvm qemu-utils libvirt-clients libvirt-daemon-system virtinst dynamips libpcap-dev \
software-properties-common ca-certificates curl gnupg2
```

---

## BGPFuzz Testing Environment Setup

This project consists of two components: the tester (BGPFuzz) and the test environment (GNS3 + GNS3 VM + network topology).

### Installing GNS3 and Loading GNS3 VM

To improve portability, we first set up GNS3 with a Python virtual environment (`gns3venv`) on Ubuntu:

1. Install VMware Workstation Pro from either the [official site](https://support.broadcom.com/group/ecx/productfiles?subFamily=VMware%20Workstation%20Pro&displayGroup=VMware%20Workstation%20Pro%2017.0%20for%20Linux&release=17.6&os=&servicePk=522391&language=EN&freeDownloads=true) or the [direct link](https://github.com/201853910/VMwareWorkstation/releases/download/16.0/VMware-Workstation-Full-16.2.5-20904516.x86_64.bundle). (I would suggest download the latest version from official site rather than the direct link)
2. Download the GNS3 VM from the [official site](https://github.com/GNS3/gns3-gui/releases/download/v2.2.54/GNS3.VM.VMware.Workstation.2.2.54.zip) and load it into VMware Workstation Pro (Keep its name GNS3 VM).
3. Install GNS3:
   ```bash
   # Run the setup script from the Routing-Protocol-Fuzzing directory:
   ./setup_gns3_env.sh
   ```

### Installing BGPFuzz

```bash
# Install the dependencies for BGPFuzz
cd Fuzz-Material
./set_env.sh
```

## Usage

1. Launch GNS3, it will automatically launch VMware and start GNS3VM, please wait for at least 1min:

```bash
# Activate the virtual environment
source GNS3-Ubuntu-Setup/venv4gns3/bin/activate
# Launch GNS3
gns3
```

2. If GNS3VM is not launched, click on GNS3's menu bar - Help - Setup Wizard - Run applicaces in a virtual machine - Next - Next - Next - VMware/refresh - Next - Finished


<img src="Figs/GNS3-1.png" alt="drawing" width="600"/>
<img src="Figs/GNS3-2.png" alt="drawing" width="600"/>
<img src="Figs/GNS3-3.png" alt="drawing" width="600"/>
<img src="Figs/GNS3-4.png" alt="drawing" width="600"/>
<img src="Figs/GNS3-5.png" alt="drawing" width="600"/>
<img src="Figs/GNS3-6.png" alt="drawing" width="600"/>


2. Load topologies for different scenarios: 
> Note: You may need to import operating system's image for routers manually if the nodes in project can't be started properly. In our project file we use Cisoco C7200 XB12 IOS.

```bash
Routing-Protocol-Fuzzing (Root directory)
├───BGP_Basic_Topology (Network topology project)
│   ├───exp0----max-prefix-failure-reproduction
│   │   └───project-files
│   │       └───dynamips
│   ├───exp1----sub-prefix-hijacks-interception-reproduction
│   │   └───project-files
│   │       └───dynamips

```
<img src="Figs/BGPFuzz-LoadTopo0.png" alt="drawing" width="600"/>
<img src="Figs/BGPFuzz-LoadTopo.png" alt="drawing" width="600"/>

4. Start all nodes
<img src="Figs/BGPFuzz-StartAllNode.png" alt="drawing" width="600"/>

5. Modify the config for BGPFuzz: The project name and the file path.
<img src="Figs/BGPFuzz-Setting.png" alt="drawing" width="600"/>

6. Fo to BGPFuzz's root directory, and run BGPFuzz with this cmd:
> Note: To enable BGPFuzz connect to GNS3VM, you may need to change the AUTH HEADER in config.py by running gns3server --local --debug and find the line containning string like Authorization': 'Basic YWRtaW46R0x2M2ExVXN4c24ySHJUb1BsRG5QRjQ4d2JjWTE5ZDdRdjZnV0tqUFlpWFNIUlFBaDM3QlBRNFByTDdsV0JqSQ=='

```bash
cd Fuzz-Material/BGPFuzz/
python3 main.py
```

1. Enter the selected node to perform testing on: In this case we select R5 and the first link.
<img src="Figs/BGPFuzz-Prompt.png" alt="drawing" width="600"/>

1. Wait for console output the bug report:
<img src="Figs/BGPFuzz-Output.png" alt="drawing" width="600"/>

## Sample Bug Report Analysis: Sub-prefix Hijack Detection

This output shows a full run of `sub-prefix-fuzzer.py` analyzing BGP prefix announcements to detect sub-prefix hijacking patterns.

### 🎯 Node and Link Selection

```text
chosen_name: R5

Available Links for the selected node:
  1. Link 1 (Connected to: R3)

Selected Project ID: 9890d5d6-5ea2-4d1c-9b81-8ce46918a321  
Selected Node ID: 181dcc4c-69c0-48e7-9a43-1f9036c14d6b  
Selected Link ID: e46d6ccc-44de-4fc2-bbd6-89cd1f37e2fc  
Configuration file retrieved successfully.  
[+] Found VM: /home/test/vmware/GNS3 VM/GNS3 VM.vmx  
[+] VM IP: 172.16.169.129  
```

### 📡 BGP Table Dump (Before Mutation)

```
textCopy code[*] Launching Telnet and sending 'show ip bgp'...
Connected to Dynamips VM "R1" (ID 1, type c7200) - Console port

BGP table version is 28, local router ID is 208.65.152.1

     Network          Next Hop            Metric LocPrf Weight Path
 r>  10.0.1.0/30      10.0.1.2                 0             0 65010 i
 *>  10.0.2.0/30      10.0.1.2                 0             0 65010 i
 *>  10.0.3.0/30      10.0.1.2                 0             0 65010 i
 *>  10.0.4.0/30      10.0.1.2                               0 65010 65020 i
 *>  208.65.152.0     10.0.1.2                               0 65010 65020 65040 i
 *>  208.65.152.0/22  0.0.0.0                  0         32768 i
 *>  208.65.153.0     10.0.1.2                               0 65010 65020 65040 i
```

------

### 🧬 Prefix Extraction

```
textCopy code[*] Extracting BGP prefixes from log...
[+] Prefixes found:
  - 10.0.1.0/30
  - 10.0.2.0/30
  - 10.0.3.0/30
  - 10.0.4.0/30
  - 208.65.152.0/22
  - 208.65.152.0/24
  - 208.65.153.0/24
```

------

### 🧪 Mutation Phase

```
textCopy codeMutation applied: no sub-prefix inserted
```

*Note: In this run, the mutation logic detected existing sub-prefixes and therefore skipped new insertion.*

------

### ⚠️ Oracle Detection Result

```
textCopy code[!] Duplicate prefix pattern detected:
 - 208.65.152.0/24 is a more specific sub-prefix of 208.65.152.0/22
 - 208.65.153.0/24 is a more specific sub-prefix of 208.65.152.0/22

[Oracle] Found 2 suspicious prefix overlaps.
```

------

### 🔄 Recovery Phase

```
textCopy code[Recovery Phase] Restoring original configuration...
[+] Stopping node 181dcc4c-69c0-48e7-9a43-1f9036c14d6b...
Node ... stopped successfully.
[+] Uploading configuration...
Configuration file uploaded successfully.
[+] Starting node ...
Node ... started successfully.
```

------


