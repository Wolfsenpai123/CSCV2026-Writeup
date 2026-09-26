#!/usr/bin/env python3
"""Reproduce Silent Room analysis from a tsk_recover extraction.

PNR, property and city are transcribed from the recovered cache images.
The flag is read from the decoded proof image, not constructed here.
"""

import argparse
import base64
import hashlib
import json
import re
import sqlite3
import struct
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


TZ = timezone(timedelta(hours=7))
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def connect_readonly(path):
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)


def validate_png(data):
    """Validate chunk bounds, CRCs, IHDR, IDAT and the final IEND."""
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("Sai key: output khong co PNG signature")
    offset = len(PNG_SIGNATURE)
    chunks = []
    dimensions = None
    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError("PNG chunk header bi cat")
        length = struct.unpack_from(">I", data, offset)[0]
        tag = data[offset + 4:offset + 8]
        end = offset + 12 + length
        if end > len(data):
            raise ValueError("PNG chunk vuot qua kich thuoc file")
        payload = data[offset + 8:offset + 8 + length]
        expected_crc = struct.unpack_from(">I", data, offset + 8 + length)[0]
        if zlib.crc32(tag + payload) & 0xFFFFFFFF != expected_crc:
            raise ValueError(f"CRC khong hop le: {tag!r}")
        if not chunks and tag != b"IHDR":
            raise ValueError("Chunk dau tien khong phai IHDR")
        if tag == b"IHDR":
            if chunks or length != 13:
                raise ValueError("IHDR khong hop le")
            dimensions = struct.unpack(">II", payload[:8])
        chunks.append(tag)
        offset = end
        if tag == b"IEND":
            if length or offset != len(data) or b"IDAT" not in chunks:
                raise ValueError("IEND hoac IDAT khong hop le")
            return dimensions, len(chunks)
    raise ValueError("Khong tim thay IEND")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("recovered", type=Path, help="Directory containing Users/A")
    parser.add_argument("--out", type=Path, default=Path("silentroom-analysis"))
    parser.add_argument("--pnr", required=True, help="PNR read from f_000033")
    parser.add_argument("--property", required=True, help="Property read from f_000054")
    parser.add_argument("--city", required=True, help="City read from f_000054")
    args = parser.parse_args()

    profile = args.recovered / "Users/A"
    chrome = profile / "AppData/Local/Google/Chrome/User Data/Default"
    cache = chrome / "Cache/Cache_Data"
    chat = profile / "AppData/Roaming/ChatApp"
    output = args.out.resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError("Output directory phai moi hoac rong de tranh ghi de")

    history = []
    with connect_readonly(chrome / "History") as db:
        for url, title, timestamp in db.execute(
            "SELECT url,title,last_visit_time FROM urls ORDER BY last_visit_time"
        ):
            date = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
                microseconds=timestamp
            )
            history.append({"time": date.astimezone(TZ).isoformat(),
                            "url": url, "title": title})

    local_state = json.loads((chat / "Local State").read_text(encoding="utf-8-sig"))
    bundle = (profile / "AppData/Local/Programs/ChatApp/resources/app.bundle.js").read_text(
        encoding="utf-8-sig"
    )
    kid = re.search(r'kid\s*:\s*"([^"]+)"', bundle).group(1)
    peer = local_state["profile"]["activePeer"]
    case_id = local_state["profile"]["caseId"]
    key_material = "|".join([kid, peer, case_id])
    aes_key = hashlib.sha256(key_material.encode("utf-8")).digest()
    messages = []
    with connect_readonly(chat / local_state["profile"]["database"]) as db:
        for mid, direction, body, timestamp in db.execute(
            "SELECT id,direction,body,created_at FROM messages ORDER BY id"
        ):
            envelope = json.loads(body)
            if envelope["alg"] != "AES-256-CBC" or envelope["kid"] != kid:
                raise ValueError("Chat envelope khong khop app.bundle.js")
            iv = base64.b64decode(envelope["iv"], validate=True)
            ciphertext = base64.b64decode(envelope["ct"], validate=True)
            plaintext = unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ciphertext), 16)
            messages.append({"id": mid, "direction": direction,
                             "time": datetime.fromtimestamp(timestamp, TZ).isoformat(),
                             "body": plaintext.decode("utf-8")})

    state_script = (cache / "f_000020").read_text(encoding="utf-8-sig")
    state_map = {int(code): name for code, name in re.findall(
        r"(\d+)\s*:\s*'([^']+)'", state_script
    )}
    old = json.loads((cache / "f_000021").read_text(encoding="utf-8-sig"))
    active = json.loads((cache / "f_000041").read_text(encoding="utf-8-sig"))
    storage = chrome / "Local Storage/leveldb"
    manifest = (storage / "MANIFEST-000001").read_text(encoding="utf-8-sig").strip()
    log_name = manifest.removeprefix("CURRENT: ")
    log = (storage / log_name).read_bytes()
    active_ref = re.search(rb"activeReservation\x00([^\x00]+)", log).group(1).decode()
    if active_ref != active["reservation"] or old["supersededBy"] != active_ref:
        raise ValueError("Local Storage va cache JSON khong khop reservation")
    room = active["roomNumber"]
    state = state_map[active["state"]]
    if f"roomNumber={room}".encode() not in log or f"state={active['state']}".encode() not in log:
        raise ValueError("Local Storage va JSON khong khop room/state")

    metadata = {}
    for line in (cache / "f_000088").read_text(encoding="utf-8-sig").splitlines():
        if "=" in line:
            name, value = line.split("=", 1)
            metadata[name] = value
    if metadata["operation"] != "XOR" or metadata["key_format"] != "UTF-8":
        raise ValueError("Proof metadata khong phai XOR voi key UTF-8")
    object_name = metadata["object"]
    if Path(object_name).name != object_name or "/" in object_name or "\\" in object_name:
        raise ValueError("Proof object khong phai basename")

    xor_key_text = "|".join([args.pnr, state, room,
                             "".join(args.property.split()), "".join(args.city.split())])
    xor_key = xor_key_text.encode("utf-8")
    encrypted = (cache / object_name).read_bytes()
    decoded = bytes(value ^ xor_key[index % len(xor_key)]
                    for index, value in enumerate(encrypted))
    dimensions, chunk_count = validate_png(decoded)

    output.mkdir(parents=True, exist_ok=True)
    for filename, value in [("history.json", history), ("messages.json", messages)]:
        (output / filename).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n",
                                      encoding="utf-8")
    for name, filename in [("f_000033", "ticket.png"), ("f_000054", "booking-preview.png")]:
        data = (cache / name).read_bytes()
        validate_png(data)
        (output / filename).write_bytes(data)
    proof = output / "location-confirmation.png"
    proof.write_bytes(decoded)
    summary = {"aes_key_material": key_material, "aes_key_hex": aes_key.hex(),
               "old_status": state_map[old["state"]], "active_reservation": active_ref,
               "room": room, "status": state, "property": args.property,
               "city": args.city, "xor_key": xor_key_text,
               "proof_sha256": hashlib.sha256(decoded).hexdigest(),
               "png_dimensions": dimensions, "png_chunks": chunk_count,
               "message_count": len(messages), "history_count": len(history)}
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
                                        encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"Read the flag from: {proof}")


if __name__ == "__main__":
    main()
