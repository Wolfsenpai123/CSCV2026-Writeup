#!/usr/bin/env python3
"""Restore the VuVT incident files; never execute the incident binaries."""

import argparse
import hashlib
import mmap
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


R = 0xE1000000000000000000000000000000


def aes_block(key, block, decrypt=False):
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    transform = cipher.decryptor() if decrypt else cipher.encryptor()
    return transform.update(block) + transform.finalize()


def gf_multiply(x, y):
    result = 0
    value = y
    for bit in range(128):
        if (x >> (127 - bit)) & 1:
            result ^= value
        value = (value >> 1) ^ (R if value & 1 else 0)
    return result


def ghash(key, ciphertext):
    # This sample uses empty AAD and a full 128-bit authentication tag.
    h = int.from_bytes(aes_block(key, bytes(16)), "big")
    accumulator = 0
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset:offset + 16].ljust(16, b"\0")
        accumulator = gf_multiply(accumulator ^ int.from_bytes(block, "big"), h)
    # The final block is [AAD bit length]_64 || [ciphertext bit length]_64.
    lengths = bytes(8) + (len(ciphertext) * 8).to_bytes(8, "big")
    accumulator = gf_multiply(accumulator ^ int.from_bytes(lengths, "big"), h)
    return accumulator.to_bytes(16, "big")


def recover_nonce(key, tag, ciphertext):
    s = ghash(key, ciphertext)
    encrypted_j0 = bytes(t ^ v for t, v in zip(tag, s))
    j0 = aes_block(key, encrypted_j0, decrypt=True)
    if j0[12:] != b"\0\0\0\1":
        raise ValueError(f"Invalid recovered J0: {j0.hex()}")
    return j0[:12]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True, help="Directory containing the .enc files")
    parser.add_argument("--out", type=Path, default=Path("recovered"))
    parser.add_argument("--memory", type=Path, help="Optional process dump for corroborating the derived key")
    parser.add_argument("--computer", default="DESKTOP-7NNKNIK")
    parser.add_argument("--pid", type=int, default=2844)
    parser.add_argument("--campaign", default="X7A91C")
    args = parser.parse_args()

    material = f"{args.computer.lower()}|{args.pid}|{args.campaign}".encode("ascii")
    key = hashlib.sha256(material).digest()
    print(f"material: {material.decode()}")
    print(f"key: {key.hex()}")

    if args.memory:
        with args.memory.open("rb") as stream:
            with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as memory:
                offset = memory.find(key)
                if offset < 0:
                    raise ValueError("Derived key not found in the supplied process dump")
                print(f"key found at dump file offset: {offset:#x}")

    paths = sorted(args.data.glob("*.enc"))
    if not paths:
        raise ValueError(f"No .enc files found in {args.data}")
    args.out.mkdir(parents=True, exist_ok=True)
    for path in paths:
        raw = path.read_bytes()
        if len(raw) < 24 or raw[:8] != b"1337DaKL":
            raise ValueError(f"Invalid file header: {path.name}")
        tag, ciphertext = raw[8:24], raw[24:]
        nonce = recover_nonce(key, tag, ciphertext)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext + tag, None)
        destination = args.out / path.name[:-4]
        if destination.exists():
            if destination.read_bytes() != plaintext:
                raise ValueError(f"Refusing to replace a differing file: {destination}")
        else:
            with destination.open("xb") as stream:
                stream.write(plaintext)
        digest = hashlib.sha256(plaintext).hexdigest()
        print(f"{destination.name}: nonce={nonce.hex()}, bytes={len(plaintext)}, sha256={digest}")


if __name__ == "__main__":
    main()
