"""Extract CRC-valid PNGs from a previously dumped process VMA; no malware execution."""

import argparse
import struct
import zlib
from pathlib import Path


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("vma_file", type=Path)
parser.add_argument("output_dir", type=Path)
args = parser.parse_args()
data = args.vma_file.read_bytes()
signature = b"\x89PNG\r\n\x1a\n"
args.output_dir.mkdir(parents=True, exist_ok=True)
search = 0
while True:
    start = data.find(signature, search)
    if start < 0:
        break
    search = start + len(signature)
    position = search
    while position + 12 <= len(data):
        length = struct.unpack_from(">I", data, position)[0]
        end = position + length + 12
        if end > len(data):
            break
        kind = data[position + 4:position + 8]
        body = data[position + 4:position + 8 + length]
        crc = struct.unpack_from(">I", data, position + 8 + length)[0]
        if zlib.crc32(body) & 0xFFFFFFFF != crc:
            break
        position = end
        if kind == b"IEND":
            destination = args.output_dir / f"capture_{start:#x}.png"
            destination.write_bytes(data[start:end])
            print(destination)
            break
