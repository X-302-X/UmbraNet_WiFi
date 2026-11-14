"""Compare the PE executable's main icon resources with the installer ICO."""
import argparse
import hashlib
import struct
from pathlib import Path


def u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def u32(data, offset):
    return struct.unpack_from("<I", data, offset)[0]


class PEIcons:
    def __init__(self, data):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("not a Windows executable")
        pe = u32(data, 0x3C)
        if data[pe:pe + 4] != b"PE\0\0":
            raise ValueError("missing PE signature")
        section_count = u16(data, pe + 6)
        optional_size = u16(data, pe + 20)
        optional = pe + 24
        magic = u16(data, optional)
        if magic not in (0x10B, 0x20B):
            raise ValueError("unsupported PE optional header")
        directory = optional + (96 if magic == 0x10B else 112)
        resource_rva = u32(data, directory + 16)
        sections = optional + optional_size
        self.sections = []
        for index in range(section_count):
            offset = sections + index * 40
            self.sections.append((u32(data, offset + 12), max(u32(data, offset + 8), u32(data, offset + 16)), u32(data, offset + 20), u32(data, offset + 16)))
        if not resource_rva:
            raise ValueError("PE has no resources")
        self.root = self.rva(resource_rva)

    def rva(self, value):
        for address, extent, raw, raw_size in self.sections:
            if address <= value < address + extent:
                delta = value - address
                if delta >= raw_size:
                    break
                return raw + delta
        raise ValueError("resource address is outside the executable")

    def entry(self, relative, number):
        directory = self.root + relative
        count = u16(self.data, directory + 12) + u16(self.data, directory + 14)
        for index in range(count):
            name, target = struct.unpack_from("<II", self.data, directory + 16 + index * 8)
            if not name & 0x80000000 and name == number:
                return target
        raise ValueError(f"resource {number} not found")

    def blob(self, resource_type, resource_id):
        kind = self.entry(0, resource_type)
        if not kind & 0x80000000:
            raise ValueError("invalid resource type directory")
        item = self.entry(kind & 0x7FFFFFFF, resource_id)
        if not item & 0x80000000:
            raise ValueError("invalid resource language directory")
        language_dir = self.root + (item & 0x7FFFFFFF)
        count = u16(self.data, language_dir + 12) + u16(self.data, language_dir + 14)
        if not count:
            raise ValueError("resource has no language entry")
        value = u32(self.data, language_dir + 20)
        if value & 0x80000000:
            raise ValueError("unexpected nested resource directory")
        data_entry = self.root + value
        offset, size = self.rva(u32(self.data, data_entry)), u32(self.data, data_entry + 4)
        result = self.data[offset:offset + size]
        if len(result) != size:
            raise ValueError("truncated resource")
        return result

    def icon_images(self, group_id):
        group = self.blob(14, group_id)
        if u16(group, 0) != 0 or u16(group, 2) != 1:
            raise ValueError("invalid PE icon group")
        count = u16(group, 4)
        if not count or len(group) < 6 + count * 14:
            raise ValueError("invalid PE icon count")
        images = []
        for index in range(count):
            entry = 6 + index * 14
            image = self.blob(3, u16(group, entry + 12))
            if len(image) != u32(group, entry + 8):
                raise ValueError("wrong size of PE icon image")
            images.append(image)
        return images


def ico_images(data):
    if u16(data, 0) != 0 or u16(data, 2) != 1:
        raise ValueError("invalid ICO")
    count = u16(data, 4)
    if not count or len(data) < 6 + count * 16:
        raise ValueError("invalid ICO count")
    images = []
    for index in range(count):
        entry = 6 + index * 16
        size, offset = u32(data, entry + 8), u32(data, entry + 12)
        image = data[offset:offset + size]
        if len(image) != size:
            raise ValueError("truncated ICO image")
        images.append(image)
    return images


def fingerprint(images):
    return sorted(hashlib.sha256(image).hexdigest() for image in images)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    parser.add_argument("icon", type=Path)
    parser.add_argument("--group-id", type=int, default=32512)
    args = parser.parse_args()
    expected = fingerprint(ico_images(args.icon.read_bytes()))
    actual = fingerprint(PEIcons(args.executable.read_bytes()).icon_images(args.group_id))
    if actual != expected:
        raise SystemExit("Setup executable icon does not match the installer icon")
    print(f"Setup executable contains the correct icon ({len(actual)} sizes)")


if __name__ == "__main__":
    main()
