# SPDX-License-Identifier: MIT
import hashlib
import io
import json
import tarfile
import unittest

from fork_preview import Entry, build, control_fields, read_archive, write_archive


def binary(marker=b"original"):
    data = bytearray(64)
    data[:7] = b"\x7fELF\x01\x01\x01"
    data[18:20] = (8).to_bytes(2, "little")
    return bytes(data) + marker


def base_ipk(payload_changes=None, control_changes=None):
    payload = {
        "opt": Entry(b"", 0o755, True),
        "opt/bin/awg-manager": Entry(binary(), 0o755),
        "opt/sbin/awg": Entry(b"original CLI", 0o755),
        "opt/etc/awg-manager/modules/bundled/version": Entry(b"module-version\n", 0o644),
        "opt/etc/awg-manager/modules/bundled/example.ko": Entry(b"original module", 0o644),
    }
    payload.update(payload_changes or {})
    control = {
        "control": Entry(b"Package: awg-manager\nVersion: 2.19.23\nArchitecture: mipsel-3.4\nMaintainer: hoaxisr\nDescription: Original\n continuation\n", 0o644),
        "postinst": Entry(b"original postinst", 0o755), "prerm": Entry(b"original prerm", 0o755),
    }
    control.update(control_changes or {})
    return write_archive({"debian-binary": Entry(b"2.0\n", 0o644),
                          "control.tar.gz": Entry(write_archive(control), 0o644),
                          "data.tar.gz": Entry(write_archive(payload), 0o644)})


def candidate(base, **changes):
    args = dict(base=base, binary=binary(b"fork"), expected_sha=hashlib.sha256(base).hexdigest(),
                version="2.19.23+ub3dqy.1", arch="mipsel-3.4", commit="a" * 40,
                license_text=b"MIT and original copyright", notes=b"Preview, not router-tested", kmod_version="module-version")
    args.update(changes)
    return build(**args)


class PreviewPackageTests(unittest.TestCase):
    def test_keeps_cli_modules_and_hooks_and_records_new_binary(self):
        base = base_ipk()
        result = candidate(base)
        self.assertEqual(result, candidate(base), "package must be reproducible")
        original = read_archive(base)
        output = read_archive(result)
        old_data = read_archive(original["data.tar.gz"].data)
        new_data = read_archive(output["data.tar.gz"].data)
        for name, entry in old_data.items():
            if name != "opt/bin/awg-manager":
                self.assertEqual(new_data[name], entry)
        self.assertEqual(new_data["opt/bin/awg-manager"].data, binary(b"fork"))
        old_control = read_archive(original["control.tar.gz"].data)
        new_control = read_archive(output["control.tar.gz"].data)
        for name in ("postinst", "prerm"):
            self.assertEqual(new_control[name], old_control[name])
        self.assertEqual(control_fields(new_control["control"].data.decode())["Version"], "2.19.23+ub3dqy.1")
        meta = json.loads(new_data["opt/share/doc/awg-manager-ub3dqy/BUILD-INFO.json"].data)
        self.assertFalse(meta["routerTested"])
        self.assertEqual(meta["binarySHA256"], hashlib.sha256(binary(b"fork")).hexdigest())

    def test_rejects_wrong_checksum_architecture_version_and_modules(self):
        base = base_ipk()
        for change in ({"expected_sha": "0" * 64}, {"arch": "mips-3.4"}, {"version": "2.20.0+ub3dqy.1"},
                       {"version": "2.19.23"}, {"kmod_version": "wrong"}, {"binary": b"not ELF"},
                       {"commit": "uncommitted"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                candidate(base, **change)

    def test_rejects_duplicate_control_and_unsafe_or_linked_archive_entries(self):
        with self.assertRaises(ValueError):
            candidate(base_ipk(control_changes={"postrm": Entry(b"new hook", 0o755)}))
        with self.assertRaises(ValueError):
            candidate(base_ipk(control_changes={"control": Entry(b"Package: awg-manager\nPackage: other\n", 0o644)}))
        for path, kind in (("../escape", tarfile.REGTYPE), ("/opt/escape", tarfile.REGTYPE),
                           ("opt/link", tarfile.SYMTYPE), ("opt/device", tarfile.CHRTYPE)):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                info = tarfile.TarInfo(path)
                info.type, info.linkname = kind, "../../escape"
                archive.addfile(info)
            with self.subTest(path=path), self.assertRaises(ValueError):
                read_archive(buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
