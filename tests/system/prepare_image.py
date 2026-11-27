"""Verify a downloaded appliance and unpack gzip/xz transport compression."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import argparse
import gzip
import hashlib
import lzma
import os
from pathlib import Path
import re
import shutil
import tempfile


def prepare_image(source, destination, expected_sha256):
    source, destination = Path(source), Path(destination)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        raise ValueError("Expected SHA-256 must contain 64 hexadecimal characters")
    if source.resolve() == destination.resolve():
        raise ValueError("Download and output image paths must differ")
    digest = hashlib.sha256()
    with source.open("rb") as downloaded:
        header = downloaded.read(6)
        downloaded.seek(0)
        for chunk in iter(lambda: downloaded.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != expected_sha256.lower():
        raise ValueError("Downloaded appliance SHA-256 does not match")
    if header.startswith(b"\x1f\x8b"):
        opener, compression = gzip.open, "gzip"
    elif header == b"\xfd7zXZ\x00":
        opener, compression = lzma.open, "xz"
    elif header.startswith(b"QFI\xfb"):
        opener, compression = open, "none"
    else:
        raise ValueError("Expected a qcow2 image, optionally compressed with gzip or xz")

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=str(destination.parent), prefix=destination.name + ".", delete=False) as output:
            temporary = Path(output.name)
            with opener(source, "rb") as image:
                if image.read(4) != b"QFI\xfb":
                    raise ValueError("Decompressed appliance is not a qcow2 image")
                image.seek(0)
                shutil.copyfileobj(image, output, length=1024 * 1024)
        os.replace(str(temporary), str(destination))
        return compression
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    arguments = parser.parse_args()
    try:
        compression = prepare_image(arguments.source, arguments.destination, arguments.sha256)
    except (OSError, ValueError, EOFError, lzma.LZMAError) as error:
        parser.exit(1, str(error) + "\n")
    print("Verified appliance download; transport compression: " + compression)
