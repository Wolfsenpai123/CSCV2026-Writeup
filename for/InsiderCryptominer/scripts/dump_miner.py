from pathlib import Path
import sys
from lime_reader import LimeReader
import json,struct,hashlib
out=Path(sys.argv[2]) if len(sys.argv)>2 else Path('recovered')
out.mkdir(parents=True,exist_ok=True)
r=LimeReader(sys.argv[1]);root=0x6ed65000;base=0x55c2d17fe000
head=r.read_virt(root,base,4096);e=struct.unpack_from('<16sHHIQQQIHHHHHH',head)
ph=[struct.unpack_from('<IIQQQQQQ',head,e[5]+i*e[9]) for i in range(e[10])]
size=max(p[2]+p[5] for p in ph if p[0]==1);data=bytearray(size)
for p in ph:
 if p[0]!=1:continue
 data[p[2]:p[2]+p[5]]=r.read_virt(root,base+p[3],p[5],pad=True)
(out/'miner_reconstructed.elf').write_bytes(data)
print('sha256',hashlib.sha256(data).hexdigest(),'bytes',len(data))
struct.pack_into('<Q',data,40,0);struct.pack_into('<HHH',data,58,0,0,0)
(out/'miner_analysis.elf').write_bytes(data)
print('payout strings')
import re
for m in re.finditer(b'payout',data):print(hex(m.start()),repr(data[max(0,m.start()-60):m.start()+80]))
