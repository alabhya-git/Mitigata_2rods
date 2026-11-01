"""Build-time only: pinned upstream releases, verified hashes, explicit output names."""

import hashlib
import io
import os
import tarfile
import urllib.request
import zipfile
from pathlib import Path

TOOLS = {
    "ffuf": (
        "https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_linux_amd64.tar.gz",
        "b2a3c725fcb9da175159682f54d6e9149f2905b00d84d155e7efc5d599975ceb",
    ),
    "katana": (
        "https://github.com/projectdiscovery/katana/releases/download/v1.8.0/katana_1.8.0_linux_amd64.zip",
        "cb027ae99d0757061b70c07a15c7a80f62c5a535ab52c4a329f80c4b0a7309d2",
    ),
    "nuclei": (
        "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_linux_amd64.zip",
        "ea63d4ae232808cd7c6bc00d0142428e231fab59dae01042246097d195835ab6",
    ),
}


def main():
    for name, (url, digest) in TOOLS.items():
        with urllib.request.urlopen(url, timeout=120) as response:
            raw = response.read(150 * 1024 * 1024 + 1)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("Release checksum mismatch: " + name)
        if url.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                binary = archive.read(name)
        else:
            with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
                entry = archive.getmember(name)
                if not entry.isfile():
                    raise ValueError("Expected a regular executable")
                binary = archive.extractfile(entry).read()
        target = Path("/usr/local/bin") / name
        target.write_bytes(binary)
        os.chmod(target, 0o755)
        print("Installed verified", name, flush=True)


if __name__ == "__main__":
    main()
