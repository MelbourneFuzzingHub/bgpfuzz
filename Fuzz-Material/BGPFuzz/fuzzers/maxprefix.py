from fuzzingbook.Fuzzer import Fuzzer
import re
import random

def force_max_prefix_one(config: str):
    print("force_max_prefix_one reached")
    remote_as_pattern = re.compile(r'^ (neighbor\s+(\d{1,3}(?:\.\d{1,3}){3})\s+remote-as\s+\d+)', re.IGNORECASE)
    lines = config.splitlines()
    output_lines = []
    mutated_part = []

    for i, line in enumerate(lines):
        output_lines.append(line)
        match = remote_as_pattern.match(line)
        if match:
            print("matched "+line)
            neighbor_ip = match.group(2)
            insert_line = f' neighbor {neighbor_ip} maximum-prefix 1 75'
            output_lines.append(insert_line)
            mutated_part.append(f"Inserted after line {i}: {insert_line.strip()}")

    return '\n'.join(output_lines), '\n'.join(mutated_part)

class MaxPrefixFuzzer(Fuzzer):
    def __init__(self, seed):
        self.seed = seed
        self.reset()

    def reset(self):
        self.population = self.seed
        self.seed_index = 0

    def mutate(self, inp):
        return force_max_prefix_one(inp)

    def fuzz(self):
        if self.seed_index < len(self.seed):
            self.inp = self.seed[self.seed_index]
            self.seed_index += 1
        else:
            self.inp, _ = self.mutate(random.choice(self.population))
        return self.mutate(self.inp)
