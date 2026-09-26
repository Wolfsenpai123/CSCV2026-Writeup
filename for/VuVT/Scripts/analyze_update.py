import argparse
import re
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OPT_DETAIL
from capstone.x86 import X86_OP_IMM, X86_OP_MEM

p = argparse.ArgumentParser()
p.add_argument('path')
p.add_argument('--around', type=lambda x: int(x, 0))
p.add_argument('--count', type=int, default=80)
p.add_argument('--end', type=lambda x: int(x, 0))
a = p.parse_args()
pe = pefile.PE(a.path)
base = pe.OPTIONAL_HEADER.ImageBase
text = next(s for s in pe.sections if s.Name.startswith(b'.text'))
raw = text.get_data()
start = base + text.VirtualAddress
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
ins = list(md.disasm(raw, start))
imported = {x.address: x.name.decode(errors='replace') if x.name else str(x.ordinal)
            for d in pe.DIRECTORY_ENTRY_IMPORT for x in d.imports}
if a.around is not None:
    near = min(range(len(ins)), key=lambda i: abs(ins[i].address - a.around))
    selected = (x for x in ins if a.around <= x.address < a.end) if a.end else ins[max(0, near - a.count//2): near + a.count//2]
    for x in selected:
        op = x.op_str
        for addr, name in imported.items():
            if f'0x{addr:x}' in op: op += ' ' + name
        print(f'{x.address:08x} {x.mnemonic:8} {op}')
else:
    for x in ins:
        if x.mnemonic == 'call' and any(y.type == X86_OP_MEM and y.mem.disp in imported for y in x.operands):
            name = imported[x.operands[0].mem.disp]
            if name.startswith('BCrypt'):
                print(f'{x.address:08x} {name}')
    b = open(a.path, 'rb').read()
    for pattern, encoding in ((rb'(?:[ -~]\x00){4,}', 'utf-16le'),
                              (rb'[ -~]{4,}', 'ascii')):
        for m in re.finditer(pattern, b):
            s = m.group().decode(encoding)
            if any(t in s.lower() for t in ('chaining', 'aes', 'sha', 'gcm', '1337', 'dakl', 'public', 'api/check', 'campaign', 'magic')):
                print(f'string {base+pe.get_rva_from_offset(m.start()):08x} {s!r}')
