import threading

from _synth import make_mbr_disk
from mounting_image.formats import open_image
from mounting_image.nbd import NBDServer
from mounting_image.nbdclient import (
    NBDClient,
    is_nbd_url,
    parse_nbd_url,
)
from mounting_image.partitions import detect


def _server(tmp_path):
    raw = make_mbr_disk()
    p = tmp_path / "disk.raw"
    p.write_bytes(raw)
    srv = NBDServer(open_image(str(p)), "127.0.0.1", 0, "evi")
    srv.serve_in_thread()
    return srv, srv.server_address[1], raw


def test_url_helpers():
    assert is_nbd_url("nbd://10.0.0.1:10809/x")
    assert is_nbd_url("127.0.0.1:10809")
    assert not is_nbd_url("C:/cases/disk.E01")
    assert not is_nbd_url("/mnt/disk.raw")
    assert parse_nbd_url("nbd://h:99/exp") == ("h", 99, "exp")
    assert parse_nbd_url("h:1234") == ("h", 1234, "")


def test_client_reads_match_source(tmp_path):
    srv, port, raw = _server(tmp_path)
    try:
        c = NBDClient("127.0.0.1", port, "evi")
        assert c.size == len(raw)
        assert c.read_only is True
        assert c.read(0, 512) == raw[:512]
        assert c.read(2048 * 512, 5) == b"PART1"
        assert c.read(len(raw) - 100, 200) == raw[-100:]
        assert b"".join(c.stream()) == raw
        c.close()
    finally:
        srv.shutdown()
        srv.server_close()


def test_client_is_an_image_for_partition_detection(tmp_path):
    srv, port, raw = _server(tmp_path)
    try:
        c = NBDClient("127.0.0.1", port, "evi")
        scheme, parts = detect(c)
        assert scheme == "mbr" and len(parts) == 2
        assert parts[0].type_label == "NTFS/exFAT"
        c.close()
    finally:
        srv.shutdown()
        srv.server_close()


def test_open_image_accepts_nbd_url(tmp_path):
    srv, port, raw = _server(tmp_path)
    try:
        img = open_image(f"nbd://127.0.0.1:{port}/evi")
        assert img.format_name == "nbd" and img.size == len(raw)
        img.close()
    finally:
        srv.shutdown()
        srv.server_close()


def test_pull_downloads_range(tmp_path):
    srv, port, raw = _server(tmp_path)
    try:
        c = NBDClient("127.0.0.1", port, "evi")
        out = tmp_path / "slice.raw"
        n = c.pull(str(out), offset=2048 * 512, length=4096)
        assert n == 4096
        assert out.read_bytes() == raw[2048 * 512:2048 * 512 + 4096]
        c.close()
    finally:
        srv.shutdown()
        srv.server_close()


def test_cli_connect_partitions(tmp_path, capsys):
    from mounting_image.cli import main
    srv, port, raw = _server(tmp_path)
    try:
        rc = main(["connect", f"nbd://127.0.0.1:{port}/evi", "--partitions"])
        assert rc == 0
        assert "NTFS/exFAT" in capsys.readouterr().out
    finally:
        srv.shutdown()
        srv.server_close()


def test_cli_connect_pull(tmp_path):
    from mounting_image.cli import main
    srv, port, raw = _server(tmp_path)
    try:
        out = tmp_path / "d.raw"
        rc = main(["connect", f"nbd://127.0.0.1:{port}/evi", "--pull",
                   str(out), "-q"])
        assert rc == 0 and out.read_bytes() == raw
    finally:
        srv.shutdown()
        srv.server_close()
