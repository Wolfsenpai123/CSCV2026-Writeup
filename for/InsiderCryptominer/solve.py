#!/usr/bin/env python3
"""Recover the two encrypted answers and optionally replay the challenge.

The offsets are file offsets in the supplied LiME image.  They are specific
to this challenge image.  The original image is no longer present in the recovered workspace;
provide it separately to rerun memory extraction.

Dependencies: pycryptodome, python-snappy, mnemonic
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import struct
from pathlib import Path

import snappy
from Crypto.Cipher import AES
from Crypto.Hash import keccak
from mnemonic import Mnemonic


VAULT_LOCAL_OFFSET = 0x5DD0E8FD
VAULT_LOCAL_SIZE = 489
VAULT_OVERFLOW_OFFSET = 0x5D1FE044
VAULT_OVERFLOW_SIZE = 2518
DERIVED_KEY_OFFSET = 0x4F8DAFE0
PAYOUT_COPIES = (0x96107B20, 0x9BE50B60, 0xA0C0DBA0)

PASSWORD_CIPHER = bytes.fromhex(
    "53e21003c11701f379068403f3ca21a9dfd3d310d49ce9b8d50ab56b23460801"
)
PASSWORD_MAC = "43f46daa1b4b46d5c301263984af14738c27f1551e97fff504b50184562294fd"
PASSWORD_SALT = "1679c885a9b62191443a1891922f9c2a"
COUNTER_SALT = "8dc852f2ee34b2bad7de792db57c6f84"
COUNTER_CIPHER = bytes.fromhex("463f2fc42804e54a6ea5cd7a73276a11")

XTEA_KEY = struct.unpack(
    "<4I", bytes.fromhex("11273a4c59687d8e90abbccddeeff102")
)
XTEA_IV = bytes.fromhex("a1b2c3d4e5f60718")
MONERO_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def read_at(image: Path, offset: int, size: int) -> bytes:
    with image.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(size)
    if len(data) != size:
        raise ValueError(f"short read at {offset:#x}: {len(data)} != {size}")
    return data


def aes_ctr(key: bytes, iv_hex: str, data: bytes) -> bytes:
    return AES.new(
        key,
        AES.MODE_CTR,
        nonce=b"",
        initial_value=bytes.fromhex(iv_hex),
    ).decrypt(data)


def decrypt_xtea_block(block: bytes) -> bytes:
    left, right = struct.unpack("<2I", block)
    total = 0xC6EF3720
    for _ in range(32):
        right = (
            right
            - ((((left << 4) ^ (left >> 5)) + left) ^
               ((total + XTEA_KEY[(total >> 11) & 3]) & 0xFFFFFFFF))
        ) & 0xFFFFFFFF
        total = (total - 0x9E3779B9) & 0xFFFFFFFF
        left = (
            left
            - ((((right << 4) ^ (right >> 5)) + right) ^
               ((total + XTEA_KEY[total & 3]) & 0xFFFFFFFF))
        ) & 0xFFFFFFFF
    return struct.pack("<2I", left, right)


def decode_monero_base58(address: str) -> bytes:
    decoded = bytearray()
    for offset in range(0, len(address), 11):
        block = address[offset : offset + 11]
        value = 0
        for char in block:
            value = value * 58 + MONERO_ALPHABET.index(char)
        decoded.extend(value.to_bytes(8 if len(block) == 11 else 5, "big"))
    return bytes(decoded)


def recover(image: Path) -> tuple[str, str]:
    local = read_at(image, VAULT_LOCAL_OFFSET, VAULT_LOCAL_SIZE)
    overflow = read_at(image, VAULT_OVERFLOW_OFFSET, VAULT_OVERFLOW_SIZE)
    # The first 22 bytes are the SQLite record header and the record key.
    structured_clone = snappy.decompress(local[22:] + overflow)
    if len(structured_clone) != 5192:
        raise ValueError("unexpected Firefox structured-clone length")
    if b"4532eb1bf34aa175" not in structured_clone:
        raise ValueError("expected Keplr vault was not recovered")

    match = re.search(rb"__uint8array__([0-9a-f]+)", structured_clone)
    if not match:
        raise ValueError("Keplr sensitive field is missing")
    sensitive = bytes.fromhex(match.group(1).decode())

    derived = read_at(image, DERIVED_KEY_OFFSET, 32)
    mac = hashlib.sha256(derived[16:] + PASSWORD_CIPHER[16:]).hexdigest()
    if mac != PASSWORD_MAC:
        raise ValueError("derived-key MAC does not match the vault")

    vault_key = aes_ctr(derived, PASSWORD_SALT, PASSWORD_CIPHER)
    counter = aes_ctr(vault_key, COUNTER_SALT, COUNTER_CIPHER)
    vault = json.loads(aes_ctr(vault_key, counter.hex(), sensitive))
    phrase = vault["mnemonic"]
    if not Mnemonic("english").check(phrase):
        raise ValueError("decrypted mnemonic fails the BIP39 checksum")

    ciphertext = read_at(image, PAYOUT_COPIES[0], 96)
    if any(read_at(image, offset, 96) != ciphertext for offset in PAYOUT_COPIES[1:]):
        raise ValueError("surviving payout copies do not agree")

    plaintext = bytearray()
    previous = XTEA_IV
    for offset in range(0, len(ciphertext), 8):
        block = ciphertext[offset : offset + 8]
        plaintext.extend(bytes(a ^ b for a, b in zip(decrypt_xtea_block(block), previous)))
        previous = block

    padding = plaintext[-1]
    if not 1 <= padding <= 8 or plaintext[-padding:] != bytes([padding]) * padding:
        raise ValueError("XTEA-CBC padding is invalid")
    payout = bytes(plaintext[:-padding]).decode("ascii")
    if len(payout) != 95:
        raise ValueError("unexpected payout-address length")

    decoded = decode_monero_base58(payout)
    if decoded[0] != 18:
        raise ValueError("payout address is not a Monero mainnet address")
    checksum = keccak.new(digest_bits=256, data=decoded[:-4]).digest()[:4]
    if checksum != decoded[-4:]:
        raise ValueError("Monero payout checksum is invalid")
    return phrase, payout


def submit(answers: list[str], host: str, port: int, output: Path) -> str:
    transcript: list[str] = []
    with socket.create_connection((host, port), timeout=10) as connection:
        connection.settimeout(15)
        for answer in answers:
            received = b""
            while "➤".encode() not in received:
                chunk = connection.recv(65536)
                if not chunk:
                    raise RuntimeError("challenge closed before the last prompt")
                received += chunk
            if b"Incorrect" in received:
                raise RuntimeError(received.decode(errors="replace"))
            transcript.append(received.decode(errors="replace"))
            transcript.append(answer + "\n")
            connection.sendall((answer + "\n").encode())

        received = b""
        while not re.search(rb"CSCV2026\{[^}]+\}", received):
            chunk = connection.recv(65536)
            if not chunk:
                raise RuntimeError("challenge closed without returning a flag")
            received += chunk
        transcript.append(received.decode(errors="replace"))

    match = re.search(rb"CSCV2026\{[^}]+\}", received)
    assert match is not None
    flag = match.group().decode()
    output.mkdir(parents=True, exist_ok=True)
    (output / "verified_replay.txt").write_text("".join(transcript))
    (output / "flag.txt").write_text(flag + "\n")
    return flag


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", type=Path, default=Path("mem.raw"))
    parser.add_argument("--output", type=Path, default=Path("recovered"))
    parser.add_argument("--host", default="113.20.103.55")
    parser.add_argument("--port", type=int, default=1336)
    parser.add_argument(
        "--no-submit",
        action="store_true",
        help="recover and print the answers without connecting to the instance",
    )
    args = parser.parse_args()

    phrase, payout = recover(args.image)
    answers = [
        "Keplr",
        "1788604050",
        "1788604175124",
        "Vietdollar",
        phrase,
        "/tmp/kworker1",
        payout,
        "AIplsforgiveme",
    ]
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "accepted_answers.json").write_text(json.dumps(answers, indent=2) + "\n")
    print(json.dumps(answers, indent=2))
    if not args.no_submit:
        print(submit(answers, args.host, args.port, args.output))


if __name__ == "__main__":
    main()
