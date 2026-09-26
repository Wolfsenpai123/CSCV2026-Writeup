#!/usr/bin/env python3
"""Recover the challenge's Snappy record; optionally rediscover its overflow page."""
import argparse
import struct
from pathlib import Path
import snappy

LOCAL_OFFSET = 0x5dd0e8fd
OVERFLOW_DATA = 0x5d1fe044


def exact(handle, offset, size):
    handle.seek(offset)
    data = handle.read(size)
    if len(data) != size:
        raise ValueError(f'Short read at {offset:#x}')
    return data


def decode(prefix, continuation):
    data = snappy.decompress(prefix + continuation)
    if len(data) != 5192 or b'4532eb1bf34aa175' not in data:
        raise ValueError('Wrong structured-clone length or vault ID')
    if b'Vietdollar' not in data or b'__uint8array__' not in data:
        raise ValueError('Missing vault metadata or sensitive field')
    return data


def find_overflow(handle, prefix):
    offset = 0
    size = handle.seek(0, 2)
    while offset < size:
        magic, version, start, end, _ = struct.unpack('<IIQQQ', exact(handle, offset, 32))
        if magic != 0x4c694d45 or end < start:
            raise ValueError(f'Invalid LiME header at {offset:#x}')
        payload = offset + 32
        length = end - start + 1
        if payload + length > size:
            raise ValueError('Truncated LiME segment')
        for chunk_offset in range(0, length, 16 * 1024 * 1024):
            chunk = exact(handle, payload + chunk_offset, min(16 * 1024 * 1024, length - chunk_offset))
            for page in range(0, len(chunk) - 4095, 4096):
                if chunk[page:page + 4] != b'\0' * 4:
                    continue
                continuation = chunk[page + 4:page + 4 + 2518]
                try:
                    result = decode(prefix, continuation)
                except (ValueError, snappy.UncompressError):
                    continue
                return payload + chunk_offset + page + 4, result
        offset = payload + length
    raise ValueError('No valid overflow candidate found')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, default=Path('recovered'))
    parser.add_argument('--scan-overflow', action='store_true')
    args = parser.parse_args()
    with args.image.open('rb') as handle:
        prefix = exact(handle, LOCAL_OFFSET, 489)[22:]
        if args.scan_overflow:
            position, data = find_overflow(handle, prefix)
        else:
            position = OVERFLOW_DATA
            data = decode(prefix, exact(handle, position, 2518))
    args.output.mkdir(parents=True, exist_ok=True)
    target = args.output / 'vault_structured_clone.bin'
    target.write_bytes(data)
    print(f'Overflow data: {position:#x}; structured clone: {len(data)} bytes')
    print(target)


if __name__ == '__main__':
    main()
