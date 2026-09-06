"""Build synthetic disk images in every supported container format."""

from __future__ import annotations

import struct
import uuid
import zlib

SECTOR = 512


# ---------------------------------------------------------------- raw disk
def make_mbr_disk(size=8 * 1024 * 1024, parts=((2048, 4096, 0x07),
                                               (8192, 4096, 0x83))) -> bytes:
    disk = bytearray(size)
    mbr = bytearray(512)
    for i, (start_lba, count, ptype) in enumerate(parts):
        off = 446 + i * 16
        mbr[off] = 0x80 if i == 0 else 0x00
        mbr[off + 4] = ptype
        struct.pack_into("<II", mbr, off + 8, start_lba, count)
        # stamp the partition's first sector so reads are verifiable
        tag = f"PART{i+1}".encode()
        disk[start_lba * SECTOR: start_lba * SECTOR + len(tag)] = tag
    mbr[510:512] = b"\x55\xaa"
    disk[0:512] = mbr
    return bytes(disk)


def make_gpt_disk(size=8 * 1024 * 1024,
                  parts=(("0fc63daf-8483-4772-8e79-3d69d8477de4", 40, 200, "linux"),
                         ("c12a7328-f81f-11d2-ba4b-00a0c93ec93b", 300, 500, "ESP"))
                  ) -> bytes:
    disk = bytearray(size)
    # protective MBR
    disk[446 + 4] = 0xEE
    struct.pack_into("<II", disk, 446 + 8, 1, size // SECTOR - 1)
    disk[510:512] = b"\x55\xaa"

    entries = bytearray(128 * 128)
    for i, (tguid, first, last, name) in enumerate(parts):
        e = bytearray(128)
        e[0:16] = uuid.UUID(tguid).bytes_le
        e[16:32] = uuid.uuid4().bytes_le
        struct.pack_into("<QQ", e, 32, first, last)
        nm = name.encode("utf-16-le")
        e[56:56 + len(nm)] = nm
        entries[i * 128:(i + 1) * 128] = e
        disk[first * SECTOR:first * SECTOR + 8] = f"GP{i+1}".encode().ljust(8, b"\0")
    disk[2 * SECTOR:2 * SECTOR + len(entries)] = entries

    hdr = bytearray(92)
    hdr[0:8] = b"EFI PART"
    struct.pack_into("<III", hdr, 8, 0x00010000, 92, 0)
    struct.pack_into("<QQ", hdr, 24, 1, size // SECTOR - 1)
    struct.pack_into("<QQ", hdr, 40, 34, size // SECTOR - 34)
    hdr[56:72] = uuid.uuid4().bytes_le
    struct.pack_into("<QII", hdr, 72, 2, 128, 128)
    disk[SECTOR:SECTOR + 92] = hdr
    return bytes(disk)


# ---------------------------------------------------------------- VHD
def _vhd_footer(disk_type: int, current_size: int, data_offset: int) -> bytes:
    f = bytearray(512)
    f[0:8] = b"conectix"
    struct.pack_into(">II", f, 8, 2, 0x00010000)
    struct.pack_into(">Q", f, 16, data_offset)
    f[28:32] = b"pyfr"
    struct.pack_into(">QQ", f, 40, current_size, current_size)
    struct.pack_into(">I", f, 60, disk_type)
    f[68:84] = uuid.uuid4().bytes
    chk = (-sum(f)) & 0xFFFFFFFF
    struct.pack_into(">I", f, 64, chk)
    return bytes(f)


def make_vhd_fixed(raw: bytes) -> bytes:
    return raw + _vhd_footer(2, len(raw), 0xFFFFFFFFFFFFFFFF)


def make_vhd_dynamic(raw: bytes, block_size=2 * 1024 * 1024) -> bytes:
    n_blocks = (len(raw) + block_size - 1) // block_size
    footer = _vhd_footer(3, len(raw), 512)
    dyn = bytearray(1024)
    dyn[0:8] = b"cxsparse"
    struct.pack_into(">Q", dyn, 8, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into(">Q", dyn, 16, 512 + 1024)          # table offset
    struct.pack_into(">I", dyn, 28, n_blocks)
    struct.pack_into(">I", dyn, 32, block_size)
    bitmap_sectors = (((block_size // SECTOR) + 7) // 8 + 511) // 512
    bat_bytes = ((4 * n_blocks) + 511) // 512 * 512
    out = bytearray()
    out += footer + dyn
    bat_start = len(out)
    out += b"\xff" * bat_bytes
    data_start_sector = (bat_start + bat_bytes) // SECTOR
    bat = []
    cursor = data_start_sector
    for b in range(n_blocks):
        block = raw[b * block_size:(b + 1) * block_size]
        if not block.strip(b"\x00"):
            bat.append(0xFFFFFFFF)
            continue
        bat.append(cursor)
        out += b"\xff" * (bitmap_sectors * SECTOR)
        padded = block.ljust(block_size, b"\x00")
        out += padded
        cursor += bitmap_sectors + block_size // SECTOR
    for b, v in enumerate(bat):
        struct.pack_into(">I", out, bat_start + b * 4, v)
    out += footer
    return bytes(out)


# ---------------------------------------------------------------- VMDK sparse
def make_vmdk_sparse(raw: bytes, grain_sectors=128, gtes_per_gt=512) -> bytes:
    capacity = (len(raw) + SECTOR - 1) // SECTOR
    grain_bytes = grain_sectors * SECTOR
    n_grains = (len(raw) + grain_bytes - 1) // grain_bytes
    n_gt = (n_grains + gtes_per_gt - 1) // gtes_per_gt

    header = bytearray(SECTOR)
    header[0:4] = b"KDMV"
    struct.pack_into("<II", header, 4, 1, 0)
    struct.pack_into("<Q", header, 12, capacity)
    struct.pack_into("<Q", header, 20, grain_sectors)
    struct.pack_into("<Q", header, 28, 0)                 # descriptorOffset
    struct.pack_into("<Q", header, 36, 0)
    struct.pack_into("<I", header, 44, gtes_per_gt)
    # layout: header | GD | GTs | grains   (all sector aligned)
    gd_sector = 1
    gd_bytes = ((4 * n_gt) + SECTOR - 1) // SECTOR * SECTOR
    gt_start_sector = gd_sector + gd_bytes // SECTOR
    gt_bytes = ((4 * gtes_per_gt) + SECTOR - 1) // SECTOR * SECTOR
    struct.pack_into("<Q", header, 56, gd_sector)

    gd = [gt_start_sector + i * (gt_bytes // SECTOR) for i in range(n_gt)]
    grains_start = gt_start_sector + n_gt * (gt_bytes // SECTOR)

    gts = [[0] * gtes_per_gt for _ in range(n_gt)]
    grain_blob = bytearray()
    cur = grains_start
    for g in range(n_grains):
        chunk = raw[g * grain_bytes:(g + 1) * grain_bytes]
        if not chunk.strip(b"\x00"):
            continue
        gt_no, ent = divmod(g, gtes_per_gt)
        gts[gt_no][ent] = cur
        grain_blob += chunk.ljust(grain_bytes, b"\x00")
        cur += grain_sectors

    out = bytearray(header)
    gd_raw = b"".join(struct.pack("<I", s) for s in gd).ljust(gd_bytes, b"\x00")
    out += gd_raw
    for gt in gts:
        out += b"".join(struct.pack("<I", s) for s in gt).ljust(gt_bytes, b"\x00")
    out += grain_blob
    return bytes(out)


# ---------------------------------------------------------------- EWF / E01
def make_e01(raw: bytes, sectors_per_chunk=64) -> bytes:
    bps = 512
    chunk_size = sectors_per_chunk * bps
    chunks = [raw[i:i + chunk_size].ljust(chunk_size, b"\x00")
              for i in range(0, max(len(raw), 1), chunk_size)]
    sector_count = len(raw) // bps

    def section(stype: bytes, body: bytes, next_off: int, here: int) -> bytes:
        size = 76 + len(body)
        desc = bytearray(76)
        desc[0:len(stype)] = stype
        struct.pack_into("<QQ", desc, 16, next_off, size)
        struct.pack_into("<I", desc, 72, zlib.adler32(bytes(desc[:72])))
        return bytes(desc) + body

    out = bytearray()
    out += b"EVF\x09\x0d\x0a\xff\x00" + b"\x01" + struct.pack("<H", 1) + b"\x00\x00"

    # volume
    vol = bytearray(1052)
    struct.pack_into("<B3xIIII", vol, 0, 0, len(chunks), sectors_per_chunk,
                     bps, sector_count)
    here = len(out)
    body_here = here + 76
    sec = section(b"volume", bytes(vol), body_here + len(vol), here)
    out += sec

    # sectors (stored, each chunk + adler32)
    sectors_here = len(out)
    sectors_body = bytearray()
    chunk_file_offsets = []
    for ch in chunks:
        chunk_file_offsets.append(sectors_here + 76 + len(sectors_body))
        sectors_body += ch + struct.pack("<I", zlib.adler32(ch))
    table_here = sectors_here + 76 + len(sectors_body)
    out += section(b"sectors", bytes(sectors_body), table_here, sectors_here)

    # table
    thdr = bytearray(24)
    struct.pack_into("<I", thdr, 0, len(chunks))
    struct.pack_into("<Q", thdr, 8, 0)                    # base offset
    tbody = bytes(thdr) + b"".join(struct.pack("<I", off & 0x7FFFFFFF)
                                   for off in chunk_file_offsets)
    done_here = table_here + 76 + len(tbody)
    out += section(b"table", tbody, done_here, table_here)

    # done
    out += section(b"done", b"", done_here, done_here)
    return bytes(out)
