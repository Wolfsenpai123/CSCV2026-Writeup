"""Derive the collector password from an already recovered machine-id file."""

import argparse
from pathlib import Path


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("machine_id_file", type=Path)
args = parser.parse_args()
machine_id = args.machine_id_file.read_bytes().splitlines()[0]
mask = 0xFFFFFFFF
x = 0x811C9DC5
y = 0x55AA55AA

for byte in machine_id:
    x = ((x ^ byte) * 0x1000193) & mask
    y = ((y * 33) ^ byte) & mask

for byte in b"K9-EXFIL-2026":
    y = ((y ^ byte) * 0x1000193) & mask
    x = ((x * 31) ^ byte) & mask

print(f"VLT9-{x:08x}-{y:08x}")
