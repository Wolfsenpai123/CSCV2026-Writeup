"""Recover the VuVT challenge files without running the incident executables.

The SHA-256 input was reconstructed from update.exe and corroborated by the
same 32-byte digest in the captured update.exe process memory.  The malware
saved each AES-GCM tag but omitted the nonce.  With the key known, the nonce
can be recovered algebraically from the tag and ciphertext:

    tag = AES_K(nonce || 00000001) xor GHASH(H, ciphertext)
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SOURCE = Path(r"D:\CTF\cscv\VuVT\Users\Public\MetaData\Data")
DEST = Path(r"D:\CTF\cscv\analysis_output\restored")
MEMORY_DUMP = Path(r"D:\CTF\cscv\analysis_output\pid.2844.dmp")
KEY_MATERIAL = b"desktop-7nnknik|2844|X7A91C"
KEY = hashlib.sha256(KEY_MATERIAL).digest()
R = 0xE1000000000000000000000000000000
MASK = (1 << 128) - 1


def aes_block(block: bytes, decrypt: bool = False) -> bytes:
    cipher = Cipher(algorithms.AES(KEY), modes.ECB())
    transform = cipher.decryptor() if decrypt else cipher.encryptor()
    return transform.update(block) + transform.finalize()


def gf_multiply(x: int, y: int) -> int:
    result = 0
    value = y
    for bit in range(128):
        if (x >> (127 - bit)) & 1:
            result ^= value
        value = (value >> 1) ^ (R if value & 1 else 0)
    return result


def ghash(ciphertext: bytes) -> bytes:
    h = int.from_bytes(aes_block(bytes(16)), "big")
    accumulator = 0
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset:offset + 16].ljust(16, b"\0")
        accumulator = gf_multiply(accumulator ^ int.from_bytes(block, "big"), h)
    lengths = (len(ciphertext) * 8) & ((1 << 64) - 1)
    accumulator = gf_multiply(accumulator ^ lengths, h)
    return accumulator.to_bytes(16, "big")


def recover_nonce(tag: bytes, ciphertext: bytes) -> bytes:
    ghash_value = ghash(ciphertext)
    encrypted_j0 = (int.from_bytes(tag, "big") ^ int.from_bytes(ghash_value, "big")).to_bytes(16, "big")
    j0 = aes_block(encrypted_j0, decrypt=True)
    if j0[12:] != b"\0\0\0\1":
        raise ValueError(f"Recovered J0 has wrong counter: {j0.hex()}")
    return j0[:12]


def main() -> None:
    memory = MEMORY_DUMP.read_bytes()
    if KEY not in memory:
        raise ValueError("Derived key was not found in the captured process memory")
    print(f"key material: {KEY_MATERIAL.decode()}")
    print(f"SHA-256/AES-256 key: {KEY.hex()}")
    DEST.mkdir(parents=True, exist_ok=True)
    for path in sorted(SOURCE.glob("*.enc")):
        raw = path.read_bytes()
        if raw[:8] != b"1337DaKL":
            raise ValueError(f"Unexpected magic in {path.name}")
        tag, ciphertext = raw[8:24], raw[24:]
        nonce = recover_nonce(tag, ciphertext)
        plaintext = AESGCM(KEY).decrypt(nonce, ciphertext + tag, None)
        destination = DEST / path.name[:-4]
        if destination.exists():
            if destination.read_bytes() != plaintext:
                raise ValueError(f"Existing restored file differs: {destination}")
        else:
            with destination.open("xb") as stream:
                stream.write(plaintext)
        print(f"{path.name} -> {destination.name}; nonce={nonce.hex()}; bytes={len(plaintext)}; sha256={hashlib.sha256(plaintext).hexdigest()}")


if __name__ == "__main__":
    main()
