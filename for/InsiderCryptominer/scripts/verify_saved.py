#!/usr/bin/env python3
"""Recheck archived ciphertext and answers without the missing RAM image or network."""
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
import solve
from Crypto.Hash import keccak
from mnemonic import Mnemonic

# secp256k1 arithmetic for the archived BIP32 public-key comparison.
PRIME = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
GENERATOR = (
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % PRIME == 0:
        return None
    if left == right:
        slope = 3 * x1 * x1 * pow(2 * y1, -1, PRIME) % PRIME
    else:
        slope = (y2 - y1) * pow((x2 - x1) % PRIME, -1, PRIME) % PRIME
    x3 = (slope * slope - x1 - x2) % PRIME
    return x3, (slope * (x1 - x3) - y1) % PRIME


def public_key(scalar):
    point = None
    current = GENERATOR
    while scalar:
        if scalar & 1:
            point = add(point, current)
        current = add(current, current)
        scalar >>= 1
    require(point is not None, 'Invalid private scalar')
    x, y = point
    return bytes([2 + (y & 1)]) + x.to_bytes(32, 'big')


def cosmos_public_key(phrase):
    seed = Mnemonic.to_seed(phrase, passphrase='')
    digest = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    key, chain = int.from_bytes(digest[:32], 'big'), digest[32:]
    require(0 < key < ORDER, 'Invalid BIP32 master key')
    for index in [0x8000002c, 0x80000076, 0x80000000, 0, 0]:
        prefix = b'\0' + key.to_bytes(32, 'big') if index & 0x80000000 else public_key(key)
        digest = hmac.new(chain, prefix + index.to_bytes(4, 'big'), hashlib.sha512).digest()
        child = int.from_bytes(digest[:32], 'big')
        require(child < ORDER, 'Invalid BIP32 child')
        key, chain = (key + child) % ORDER, digest[32:]
        require(key != 0, 'Zero BIP32 child')
    return public_key(key).hex()


def main():
    material = json.loads((BASE / 'evidence/crypto_material.json').read_text())
    expected = json.loads((BASE / 'evidence/accepted_answers.json').read_text())
    derived = bytes.fromhex(material['derived_key'])
    cipher = bytes.fromhex(material['password_cipher'])
    require(cipher == solve.PASSWORD_CIPHER, 'Password ciphertext changed')
    mac = hashlib.sha256(derived[16:] + cipher[16:]).hexdigest()
    require(mac == material['user_password_mac'] == solve.PASSWORD_MAC, 'MAC mismatch')
    vault_key = solve.aes_ctr(derived, material['user_password_salt'], cipher)
    counter = solve.aes_ctr(vault_key, material['aes_counter_salt'], bytes.fromhex(material['aes_counter_cipher']))
    decrypted = json.loads(solve.aes_ctr(vault_key, counter.hex(), bytes.fromhex(material['sensitive_ciphertext'])))
    phrase = decrypted['mnemonic']
    require(phrase == expected[4], 'Mnemonic differs from the accepted answer')
    require(Mnemonic('english').check(phrase), 'Invalid BIP39 checksum')
    pub = cosmos_public_key(phrase)
    require(pub == material['public_key'], 'Vault public key mismatch')

    ciphertext = bytes.fromhex(material['payout']['ciphertext'])
    require(len(ciphertext) == 96, 'Wrong payout ciphertext length')
    plaintext = bytearray()
    previous = solve.XTEA_IV
    for offset in range(0, len(ciphertext), 8):
        block = ciphertext[offset:offset + 8]
        plaintext.extend(a ^ b for a, b in zip(solve.decrypt_xtea_block(block), previous))
        previous = block
    padding = plaintext[-1]
    require(1 <= padding <= 8 and plaintext[-padding:] == bytes([padding]) * padding, 'Bad XTEA padding')
    payout = bytes(plaintext[:-padding]).decode('ascii')
    require(payout == expected[6] == material['payout']['address'], 'Payout address mismatch')
    require(len(payout) == 95, 'Wrong Monero address length')
    decoded = solve.decode_monero_base58(payout)
    require(len(decoded) == 69 and decoded[0] == 18, 'Wrong Monero address format')
    require(keccak.new(digest_bits=256, data=decoded[:-4]).digest()[:4] == decoded[-4:], 'Bad Monero checksum')

    transcript = (BASE / 'evidence/verified_replay.txt').read_text()
    prompts = re.findall(r'\[(\d)/8\]', transcript)
    answers = re.findall(r'^➤ (.+)$', transcript, re.MULTILINE)
    require(prompts == [str(i) for i in range(1, 9)], 'Incomplete archived quiz')
    require(answers == expected, 'Archived responses differ from answer list')
    require(transcript.count('Excellent! Spot on.') == 8 and 'Incorrect' not in transcript, 'Archive is not an 8/8 successful replay')
    flag = re.search(r'CSCV2026\{[0-9a-f]{64}\}', transcript)
    require(flag is not None, 'No server flag in archived transcript')
    print(json.dumps({
        'source': 'Archived ciphertext and transcript; no new memory extraction or network request',
        'mac_valid': True, 'bip39_valid': True,
        'mnemonic': phrase, 'derivation_path': "m/44'/118'/0'/0/0",
        'public_key': pub, 'public_key_matches_vault': True,
        'xtea_padding_valid': True, 'monero_checksum_valid': True,
        'payout_address': payout, 'accepted_answers_in_archive': 8,
        'flag_from_archived_server_transcript': flag.group(),
    }, indent=2))


if __name__ == '__main__':
    main()
