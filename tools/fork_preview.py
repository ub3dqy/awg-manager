#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build an offline preview IPK; never install it or execute package hooks."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
from dataclasses import dataclass

LIMIT = 128 * 1024 * 1024
ARCHES = {"mipsel-3.4": (1, 1, 8), "mips-3.4": (1, 2, 8), "aarch64-3.10": (2, 1, 183)}


@dataclass(frozen=True)
class Entry:
    data: bytes
    mode: int
    directory: bool = False


def read_file(path: Path) -> bytes:
    if not path.is_file() or path.stat().st_size > LIMIT:
        raise ValueError(f"Missing or oversized input: {path.name}")
    with path.open("rb") as stream:
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ValueError("Input exceeds size limit")
    return data


def read_archive(data: bytes) -> dict[str, Entry]:
    entries: dict[str, Entry] = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for index, member in enumerate(archive):
            path = PurePosixPath(member.name)
            if index >= 10000 or path.is_absolute() or ".." in path.parts or "\\" in member.name or "\x00" in member.name:
                raise ValueError("Unsafe archive member")
            name = str(path)
            if name == "." and member.isdir():
                continue
            if name in entries or name == "." or not (member.isfile() or member.isdir()):
                raise ValueError("Duplicate, linked or special archive member")
            if member.mode & 0o7000 or member.size < 0 or member.size > LIMIT:
                raise ValueError("Unsafe archive mode or size")
            total += member.size
            if total > 2 * LIMIT:
                raise ValueError("Expanded archive exceeds size limit")
            content = b""
            if member.isfile():
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("Unreadable archive member")
                content = stream.read(member.size + 1)
                if len(content) != member.size:
                    raise ValueError("Truncated archive member")
            entries[name] = Entry(content, member.mode, member.isdir())
    return entries


def write_archive(entries: dict[str, Entry]) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for name, entry in entries.items():
                info = tarfile.TarInfo("./" + name)
                info.mode, info.uid, info.gid, info.mtime = entry.mode, 0, 0, 0
                info.type = tarfile.DIRTYPE if entry.directory else tarfile.REGTYPE
                info.size = 0 if entry.directory else len(entry.data)
                archive.addfile(info, None if entry.directory else io.BytesIO(entry.data))
    return buffer.getvalue()


def check_elf(data: bytes, arch: str) -> None:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("Daemon is not an ELF binary")
    byteorder = "little" if data[5] == 1 else "big"
    actual = (data[4], data[5], int.from_bytes(data[18:20], byteorder))
    if actual != ARCHES[arch]:
        raise ValueError(f"Wrong daemon architecture for {arch}")


def control_fields(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line[0].isspace():
            continue
        if ":" not in line:
            raise ValueError("Malformed package control")
        key, value = line.split(":", 1)
        if key in result:
            raise ValueError("Duplicate package control field")
        result[key] = value.strip()
    return result


def build(base: bytes, binary: bytes, expected_sha: str, version: str, arch: str,
          commit: str, license_text: bytes, notes: bytes, kmod_version: str) -> bytes:
    if arch not in ARCHES or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise ValueError("Invalid architecture or expected SHA256")
    if hashlib.sha256(base).hexdigest() != expected_sha:
        raise ValueError("Base IPK checksum mismatch")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"\d+\.\d+\.\d+\+ub3dqy\.\d+", version):
        raise ValueError("A full source commit and explicit ub3dqy version are required")
    outer = read_archive(base)
    if set(outer) != {"debian-binary", "control.tar.gz", "data.tar.gz"} or any(e.directory for e in outer.values()):
        raise ValueError("Unexpected IPK container layout")
    if outer["debian-binary"].data.strip() != b"2.0":
        raise ValueError("Unsupported IPK format")
    control = read_archive(outer["control.tar.gz"].data)
    if set(control) != {"control", "postinst", "prerm"}:
        raise ValueError("Unexpected package control hooks; review the new base package first")
    payload = read_archive(outer["data.tar.gz"].data)
    if any(name != "opt" and not name.startswith("opt/") for name in payload):
        raise ValueError("Unexpected payload outside /opt")
    if "control" not in control or control["control"].directory:
        raise ValueError("Missing package control")
    text = control["control"].data.decode("utf-8")
    fields = control_fields(text)
    if fields.get("Package") != "awg-manager" or fields.get("Architecture") != arch:
        raise ValueError("Base package name or architecture does not match")
    if fields.get("Version") != version.split("+", 1)[0]:
        raise ValueError("Preview must use the same base version as its original IPK")
    for name in ("postinst", "prerm"):
        if name not in control or control[name].directory:
            raise ValueError("Missing package lifecycle hook")
    binary_path = "opt/bin/awg-manager"
    if binary_path not in payload or payload[binary_path].directory:
        raise ValueError("Base IPK has no daemon")
    check_elf(payload[binary_path].data, arch)
    check_elf(binary, arch)
    bundled = payload.get("opt/etc/awg-manager/modules/bundled/version")
    if bundled is None or bundled.data.decode("ascii").strip() != kmod_version:
        raise ValueError("Bundled module version does not match the source build")
    payload[binary_path] = Entry(binary, payload[binary_path].mode)
    metadata = {
        "distribution": "ub3dqy-preview", "version": version, "architecture": arch,
        "sourceCommit": commit, "baseVersion": fields["Version"], "baseSHA256": expected_sha,
        "binarySHA256": hashlib.sha256(binary).hexdigest(), "routerTested": False,
        "selfUpdates": "manual", "source": "https://github.com/ub3dqy/awg-manager",
    }
    docdir = "opt/share/doc/awg-manager-ub3dqy"
    for directory in ("opt/share", "opt/share/doc", docdir):
        if directory in payload and not payload[directory].directory:
            raise ValueError("Documentation path collides with a file")
        payload.setdefault(directory, Entry(b"", 0o755, True))
    docs = {"LICENSE": license_text, "FORK_PREVIEW.md": notes,
            "BUILD-INFO.json": (json.dumps(metadata, indent=2) + "\n").encode()}
    for name, data in docs.items():
        key = docdir + "/" + name
        if key in payload:
            raise ValueError("Base IPK already contains fork metadata")
        payload[key] = Entry(data, 0o644)
    for key, value in {"Version": version, "Maintainer": "Dima Mak / ub3dqy",
                       "Description": "AWG Manager (ub3dqy preview)"}.items():
        if key not in fields:
            raise ValueError(f"Missing package field: {key}")
        text = re.sub(r"^" + key + r":.*$", key + ": " + value, text, count=1, flags=re.MULTILINE)
    control["control"] = Entry(text.encode(), control["control"].mode)
    return write_archive({"debian-binary": Entry(b"2.0\n", 0o644),
                          "control.tar.gz": Entry(write_archive(control), 0o644),
                          "data.tar.gz": Entry(write_archive(payload), 0o644)})


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("base-ipk", "binary", "base-sha256", "version", "arch", "source-commit", "kmod-version", "output"):
        parser.add_argument("--" + key, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    output = Path(args.output)
    if output.exists():
        parser.error("Output already exists; choose a new filename")
    artifact = build(read_file(Path(args.base_ipk)), read_file(Path(args.binary)),
                     args.base_sha256.lower(), args.version, args.arch, args.source_commit,
                     read_file(repo / "LICENSE"), read_file(repo / "FORK_PREVIEW.md"), args.kmod_version)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation avoids silently replacing an earlier reviewed artifact.
    with output.open("xb") as stream:
        stream.write(artifact)
    print(json.dumps({"file": output.name, "bytes": len(artifact),
                      "sha256": hashlib.sha256(artifact).hexdigest()}))


if __name__ == "__main__":
    main()
