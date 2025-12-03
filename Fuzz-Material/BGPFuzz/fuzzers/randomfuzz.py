
from fuzzingbook.Fuzzer import Fuzzer
import random
import re
from config import network_config_grammar


class MyBaselineFuzzer(Fuzzer):
    def __init__(self, seed):
        self.seed = seed
        self.reset()

    def reset(self):
        self.population = self.seed
        self.seed_index = 0

    def mutate(self, inp):
        lines = inp.splitlines()
        mutated_lines = []
        for line in lines:
            if "network" in line and "mask" in line:
                parts = line.split()
                if len(parts) >= 4:
                    parts[1] = "{}.{}.{}.{}".format(*[random.randint(255,999) for _ in range(4)])
                    parts[3] = "255.255.255.0"
                    line = " ".join(parts)
            mutated_lines.append(line)
        return "\n".join(mutated_lines), "random IP/mask tweak"

    def fuzz(self):
        if self.seed_index < len(self.seed):
            self.inp = self.seed[self.seed_index]
            self.seed_index += 1
        else:
            self.inp, _ = self.mutate(random.choice(self.population))
        return self.mutate(self.inp)