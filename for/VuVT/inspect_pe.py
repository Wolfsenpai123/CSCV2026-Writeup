"""Static PE inspection helper for the 32-bit VuVT update.exe sample."""

import argparse
import re
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from capstone.x86 import X86_OP_MEM


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("path", type=Path)
parser.add_argument("--around", type=lambda x: int(x, 0))
parser.add_argument("--end", type=lambda x: int(x, 0))
parser.add_argument("--count", type=int, default=80)
args = parser.parse_args()
pe = pefile.PE(str(args.path))
if pe.FILE_HEADER.Machine != 0x14C:
    raise SystemExit("This helper expects the x86 PE from the VuVT sample")
base = pe.OPTIONAL_HEADER.ImageBase
section = next(s for s in pe.sections if s.Name.startswith(b".text"))
disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
disassembler.detail = True
instructions = list(disassembler.disasm(section.get_data(), base + section.VirtualAddress))
imports = {item.address: item.name.decode(errors="replace") if item.name else str(item.ordinal)
           for dll in pe.DIRECTORY_ENTRY_IMPORT for item in dll.imports}

if args.around is not None:
    nearest = min(range(len(instructions)), key=lambda i: abs(instructions[i].address - args.around))
    if args.end:
        selected = [i for i in instructions if args.around <= i.address < args.end]
    else:
        selected = instructions[max(0, nearest - args.count // 2):nearest + args.count // 2]
    for instruction in selected:
        operands = instruction.op_str
        for address, name in imports.items():
            if f"0x{address:x}" in operands:
                operands += " " + name
        print(f"{instruction.address:08x} {instruction.mnemonic:8} {operands}")
else:
    print(f"Machine: x86; ImageBase: {base:#x}")
    for instruction in instructions:
        if instruction.mnemonic != "call":
            continue
        for operand in instruction.operands:
            if operand.type == X86_OP_MEM and operand.mem.disp in imports:
                name = imports[operand.mem.disp]
                if name.startswith("BCrypt"):
                    print(f"{instruction.address:08x} {name}")
    data = args.path.read_bytes()
    for pattern, encoding in ((rb"(?:[ -~]\x00){4,}", "utf-16le"), (rb"[ -~]{4,}", "ascii")):
        for match in re.finditer(pattern, data):
            value = match.group().decode(encoding)
            if any(word in value.lower() for word in
                   ("chaining", "aes", "sha", "gcm", "1337", "dakl", "public", "api/check", "campaign", "magic")):
                address = base + pe.get_rva_from_offset(match.start())
                print(f"string {address:08x} {value!r}")
