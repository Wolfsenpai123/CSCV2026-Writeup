"""Join original challenge ZIP parts, verify SHA-256, and extract the evidence."""

import argparse
import hashlib
import re
import zipfile
from pathlib import Path


BUFFER_SIZE = 8 * 1024 * 1024


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while block := source.read(BUFFER_SIZE):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('download_dir', type=Path, help='Directory containing all five dist.zip parts')
    parser.add_argument('case_root', type=Path, help='Evidence is extracted into case_root/dist')
    parser.add_argument('--checksums', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'Attachment' / 'SHA256SUMS.txt')
    args = parser.parse_args()
    expected = {}
    for line in args.checksums.read_text(encoding='utf-8').splitlines():
        digest, filename = line.split(maxsplit=1)
        expected[filename] = digest
    names = sorted(name for name in expected if re.fullmatch(r'dist\.zip\.\d{3}', name))
    if names != [f'dist.zip.{index:03d}' for index in range(1, 6)]:
        raise ValueError('The checksum file must describe exactly five archive parts')
    download_dir = args.download_dir.resolve()
    archive_path = download_dir / 'dist.zip'
    if archive_path.exists():
        if file_hash(archive_path) != expected['dist.zip']:
            raise ValueError(f'Existing archive has an unexpected SHA-256: {archive_path}')
        print('Existing dist.zip matches SHA-256; reusing it', flush=True)
    else:
        for name in names:
            if file_hash(download_dir / name) != expected[name]:
                raise ValueError(f'Part SHA-256 mismatch: {name}')
            print(f'Verified {name}', flush=True)
        with archive_path.open('xb') as destination:
            for name in names:
                with (download_dir / name).open('rb') as source:
                    while block := source.read(BUFFER_SIZE):
                        destination.write(block)
        if file_hash(archive_path) != expected['dist.zip']:
            raise ValueError('Reassembled archive SHA-256 mismatch')
        print('Reassembled dist.zip matches SHA-256', flush=True)
    evidence_dir = args.case_root.resolve() / 'dist'
    evidence_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        if len(entries) != 2 or {entry.filename for entry in entries} != {'mem.dmp', 'network.pcapng'}:
            raise ValueError('Unexpected archive contents')
        for entry in entries:
            target = evidence_dir / entry.filename
            checksum = expected['dist/' + entry.filename]
            if target.exists():
                if file_hash(target) != checksum:
                    raise ValueError(f'Existing evidence SHA-256 mismatch: {target}')
                print(f'Existing evidence matches SHA-256: {target}', flush=True)
                continue
            digest = hashlib.sha256()
            with archive.open(entry) as source, target.open('xb') as destination:
                while block := source.read(BUFFER_SIZE):
                    destination.write(block)
                    digest.update(block)
            if digest.hexdigest() != checksum:
                raise ValueError(f'Extracted evidence SHA-256 mismatch: {target}')
            print(f'Extracted and verified {target}', flush=True)


if __name__ == '__main__':
    main()
