"""Read-only, offline verification of the saved Q1 and Q2 evidence."""

import hashlib
import mmap
import struct
import argparse
from pathlib import Path


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("case_root", type=Path, help="Root containing dist and scratch")
ROOT = parser.parse_args().case_root.resolve()
MEMORY = ROOT / "dist" / "mem.dmp"
COLLECTOR = ROOT / "scratch" / "sys_audit_collector_from_mega.elf"
CACHE_PAGE = ROOT / "scratch" / "raw_cachepage_0.bin"


def check_memory():
    expected = {
        0x1E9333EB3: b'WKgaKPK93KU{"m":"tommyxiaomihackerbox@gmail.com"',
        0x1E933404E: b'E9g45elPHvo{"m":"orbitjacklane@gmail.com"',
        0x1EA06AA0E: b"4qpXAS4L",
        0x1EA06AA7E: b"sys_audit_collector",
        0x1EA06AAA6: b'{"u":"WKgaKPK93KU",',
    }
    print("Q1: offsets below are byte offsets in dist/mem.dmp")
    with MEMORY.open("rb") as source:
        with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as image:
            for offset, marker in expected.items():
                actual = image[offset:offset + len(marker)]
                assert actual == marker, f"Evidence mismatch at {offset:#x}"
                print(f"  {offset:#x}: {actual.decode('ascii')}")
            raw_page_offset = 0x3401E040
            raw_page = image[raw_page_offset:raw_page_offset + 4096]
            assert raw_page == CACHE_PAGE.read_bytes()
            print(f"  Cache page equals memory bytes at file offset {raw_page_offset:#x}")


def check_elf():
    data = COLLECTOR.read_bytes()
    cache = CACHE_PAGE.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert len(data) == 23360
    assert digest == "9ec3d41b5db1baee571dbe1bebff4774b85d61e046edce96a86dd489644ce2e7"
    assert len(cache) == 4096 and data[:4096] == cache
    assert data[:6] == b"\x7fELF\x02\x01"
    header = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    _, machine, _, entry, phoff, shoff, _, _, phsize, phnum, shsize, shnum, _ = header
    assert machine == 62
    assert phoff + phsize * phnum <= len(data)
    assert shoff + shsize * shnum <= len(data)
    print("Q2:")
    print(f"  Artifact: {COLLECTOR}")
    print(f"  Size: {len(data)} bytes")
    print(f"  SHA-256: {digest}")
    print(f"  First 4096 bytes equal saved cache page: {data[:4096] == cache}")
    print(f"  Cache page SHA-256: {hashlib.sha256(cache).hexdigest()}")
    print(f"  ELF: x86-64, entry {entry:#x}; program and section tables fit")
    entry_in_executable_segment = False
    for index in range(phnum):
        ptype, flags, offset, vaddr, _, filesz, memsz, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phsize
        )
        if ptype != 1:
            continue
        assert offset + filesz <= len(data)
        contains_entry = vaddr <= entry < vaddr + memsz
        entry_in_executable_segment |= contains_entry and bool(flags & 1)
        print(
            f"  PT_LOAD {index}: offset={offset:#x}, address={vaddr:#x}, "
            f"file_size={filesz:#x}, flags={flags}, contains_entry={contains_entry}"
        )
    assert entry_in_executable_segment


if __name__ == "__main__":
    check_memory()
    check_elf()
