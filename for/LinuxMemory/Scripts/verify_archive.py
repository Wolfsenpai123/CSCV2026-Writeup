"""Read six captured ZIP entries and verify plaintext sizes and CRC32 offline."""

import argparse
import struct
import zlib
from pathlib import Path


OFFSETS = (0x1A8B26A, 0x1A8B3F8, 0x1A8B7A0, 0x1A8BA51, 0x1A8BC0B, 0x1A8BC96)


def crc_table():
    result = []
    for value in range(256):
        for _ in range(8):
            value = (value >> 1) ^ (0xEDB88320 if value & 1 else 0)
        result.append(value)
    return result


TABLE = crc_table()


def decrypt_zipcrypto(ciphertext, password):
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(byte):
        keys[0] = (keys[0] >> 8) ^ TABLE[(keys[0] ^ byte) & 0xFF]
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        byte = keys[1] >> 24
        keys[2] = (keys[2] >> 8) ^ TABLE[(keys[2] ^ byte) & 0xFF]

    for byte in password:
        update(byte)
    plain = bytearray()
    for byte in ciphertext:
        value = (keys[2] & 0xFFFF) | 2
        byte ^= ((value * (value ^ 1)) >> 8) & 0xFF
        plain.append(byte)
        update(byte)
    return bytes(plain)


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("memory_image", type=Path)
parser.add_argument("password")
args = parser.parse_args()
with args.memory_image.open("rb") as source:
    for offset in OFFSETS:
        source.seek(offset)
        header = source.read(30)
        if header[:4] != b"PK\x03\x04":
            raise SystemExit(f"No local ZIP header at file offset {offset:#x}")
        _, flags, method, _, _, crc, compressed_size, size, name_size, extra_size = (
            struct.unpack("<HHHHHIIIHH", header[4:])
        )
        name = source.read(name_size).decode("utf-8", errors="replace")
        source.read(extra_size)
        if not flags & 1 or method != 0:
            raise SystemExit(f"Unexpected ZIP mode for {name}")
        plain = decrypt_zipcrypto(source.read(compressed_size), args.password.encode("utf-8"))
        data = plain[12:]
        actual_crc = zlib.crc32(data) & 0xFFFFFFFF
        valid = len(data) == size and actual_crc == crc
        print(f"{offset:#x} {name}: size={len(data)}/{size} CRC={actual_crc:08x}/{crc:08x} {'OK' if valid else 'FAIL'}")
        if not valid:
            raise SystemExit("Password or captured bytes failed verification")
