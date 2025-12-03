from fuzzingbook.Fuzzer import Fuzzer
import ipaddress
import re
import random
from prefix import get_prefix, get_subnet

class SubPrefixFuzzer(Fuzzer):
    def __init__(self, seed, telnet_port):
        self.seed = seed
        self.telnet_port = telnet_port
        self.prev_subnet_count = 0  # Track previous count of subnet prefixes
        self.reset()

    def reset(self):
        self.population = self.seed
        self.seed_index = 0

    def get_subprefix(self, prefix):
        if prefix.prefixlen >= 30:
            return None
        return list(prefix.subnets(new_prefix=prefix.prefixlen + 2))[0]

    # The pfxs is provided by main function, it should decide the candidate pfxs: 
    # if there is no proper subnet prefix, then no need to announce bgp sub network
    # if there is proper subnet prefix, then we can announce bgp sub network

    def mutate(self, inp, pfxs, strategy_hint=None):
        """
        Mutate the input config by inserting one sub-prefix-related config block.
        Randomly chooses one of:
        - 'interface': Insert Loopback
        - 'bgp': Insert BGP network statement
        - 'staticroute': Insert static route to Null0
        """
        if not pfxs:
            return inp, "no sub-prefix inserted"

        lines = inp.splitlines()
        result = []
        inserted = False
        info = ""
        near_interface = False

        strategy = strategy_hint or random.choice(["interface", "bgp", "staticroute"])

        for line in lines:
            result.append(line)

            if inserted:
                continue

            # Track if we're in interface section
            if re.match(r'^\s*interface\b', line):
                near_interface = True

            # Strategy 1: Insert Loopback + static route between '!'s after interface
            if strategy == "interface" and re.match(r'^\s*!\s*$', line) and near_interface:
                candidates = [p for p in pfxs if p.prefixlen < 30]
                if not candidates:
                    continue
                base = random.choice(candidates)
                sub = self.get_subprefix(base)
                if sub:
                    ip_parts = list(sub.network_address.packed)
                    ip_parts[3] = 1
                    sub_ip = str(ipaddress.IPv4Address(bytes(ip_parts)))
                    # sub_ip = str(sub.network_address)            
                    sub_mask = str(sub.netmask)
                    int_no = int(random.random() * 10000)
                    indent = re.match(r'^(\s*)', line).group(1)

                    result.append("!")
                    result.append(f"{indent}interface Loopback{int_no}")
                    result.append(f"{indent} ip address {sub_ip} {sub_mask}")
                    result.append("!")
                    inserted = True
                    info = f"[interface] Inserted Loopback{int_no} for {sub_ip} from {base}"

            # Strategy 2: Insert network under router bgp block
            if strategy == "bgp" and re.match(r'\s*network\s+\d+\.\d+\.\d+\.\d+', line):
                candidates = [p for p in pfxs if p.prefixlen < 30]
                if not candidates:
                    continue
                base = random.choice(candidates)
                # sub = self.get_subprefix(base)
                # if sub:
                sub = base
                sub_ip = str(base.network_address)
                sub_mask = str(base.netmask)
                indent = re.match(r'^(\s*)', line).group(1)
                result.append(f"{indent}network {sub_ip} mask {sub_mask}")
                inserted = True
                info = f"[bgp] Inserted network {sub} from {base}"

            # Strategy 3: Insert a static route to Null0 at any '!' after interface
            if strategy == "staticroute" and re.match(r'^\s*!\s*$', line) and near_interface:
                candidates = [p for p in pfxs if p.prefixlen < 30]
                if not candidates:
                    continue
                base = random.choice(candidates)
                sub = self.get_subprefix(base)
                if sub:
                    sub_ip = str(sub.network_address)
                    sub_mask = str(sub.netmask)
                    indent = re.match(r'^(\s*)', line).group(1)
                    result.append("!")                
                    result.append(f"{indent}ip route {sub_ip} {sub_mask} Null0")
                    result.append("!")
                    inserted = True
                    info = f"[staticroute] Inserted static route for {sub} from {base}"
        if strategy_hint == 'bgp':
            print('\n'.join(result))
        self.population.append('\n'.join(result))
        return '\n'.join(result), info if inserted else "no sub-prefix inserted"

    def fuzz(self):
        # Get the information of the selected node
        pfxs = [ipaddress.IPv4Network(p) for p in get_prefix(self.telnet_port)]
        subnet_pfxs = [ipaddress.IPv4Network(p) for p in get_subnet(self.telnet_port)]

        # Prefer strategy 2 (bgp) if the number of subnets is increasing
        strategy_hint = "bgp" if len(subnet_pfxs) > self.prev_subnet_count else random.choice(["interface", "staticroute"])
        self.prev_subnet_count = len(subnet_pfxs)

        # Choose from seed or mutate existing population
        if self.seed_index < len(self.seed):
            self.inp = self.seed[self.seed_index]
            self.seed_index += 1
        else:
            self.inp, _ = self.mutate(random.choice(self.population), pfxs, strategy_hint)

        print(f'[debug-info:] the strategy is {strategy_hint}, the prefix:')
        if strategy_hint == "bgp":
            for pfx in subnet_pfxs:
                print(f"  - {pfx}")
        else:
            for pfx in pfxs:
                print(f"  - {pfx}")

        return self.mutate(self.inp, subnet_pfxs, strategy_hint) if strategy_hint == "bgp" else self.mutate(self.inp, pfxs, strategy_hint)
