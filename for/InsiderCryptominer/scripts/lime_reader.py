"""Read physical memory and x86-64 virtual addresses from this LiME image."""
import struct
from pathlib import Path
class LimeReader:
 def __init__(self,path):
  self.f=open(path,'rb');self.segs=[]
  while True:
   hdr=self.f.read(32)
   if len(hdr)<32:break
   magic,ver,start,end,_=struct.unpack('<IIQQQ',hdr)
   assert magic==0x4c694d45
   pos=self.f.tell();self.segs.append((pos,start,end));self.f.seek(end-start+1,1)
 def read_phys(self,address,size):
  for offset,start,end in self.segs:
   if start<=address and address+size-1<=end:
    self.f.seek(offset+address-start);return self.f.read(size)
  raise ValueError(f'Unmapped physical address {address:#x}')
 def translate(self,root,va):
  table=root&0xffffffffff000
  for level,shift in enumerate([39,30,21,12]):
   entry=struct.unpack('<Q',self.read_phys(table+8*((va>>shift)&511),8))[0]
   if not entry&1:raise ValueError(f'Nonresident virtual address {va:#x}')
   if level in [1,2] and entry&128:
    return (entry&0x000ffffffffff000&~((1<<shift)-1))+(va&((1<<shift)-1))
   table=entry&0x000ffffffffff000
  return table+(va&4095)
 def read_virt(self,root,va,size,pad=False):
  data=bytearray()
  while len(data)<size:
   take=min(4096-(va&4095),size-len(data))
   try:b=self.read_phys(self.translate(root,va),take)
   except ValueError:
    if not pad:raise
    b=b'\0'*take
   data.extend(b);va+=take
  return bytes(data)
