"""Inspect universal Mach-O sections independently of the Rust patcher."""

import struct


def architectures(data):
    assert data[:4] == bytes.fromhex("cafebabe")
    count = struct.unpack_from(">I", data, 4)[0]
    result = {}
    for i in range(count):
        cpu, subtype, offset, size, align = struct.unpack_from(
            ">IIIII", data, 8 + 20 * i
        )
        member = data[offset : offset + size]
        assert len(member) == size and member[:4] == bytes.fromhex("cffaedfe")
        ncmds = struct.unpack_from("<I", member, 16)[0]
        position = 32
        sections = {}
        for _ in range(ncmds):
            command, length = struct.unpack_from("<II", member, position)
            assert length >= 8 and position + length <= len(member)
            if command == 0x19:
                nsects = struct.unpack_from("<I", member, position + 64)[0]
                for index in range(nsects):
                    fields = struct.unpack_from(
                        "<16s16sQQIIIIIIII", member, position + 72 + 80 * index
                    )
                    name, segment, _, section_size, file_offset, _, _, _, flags, *_ = (
                        fields
                    )
                    if flags & 0xFF in (1, 12, 18):
                        continue  # zero-fill has no on-disk bytes
                    key = (
                        segment.split(b"\0", 1)[0].decode(),
                        name.split(b"\0", 1)[0].decode(),
                    )
                    sections[key] = member[file_offset : file_offset + section_size]
                    assert len(sections[key]) == section_size
            position += length
        result[cpu] = sections
    return result
