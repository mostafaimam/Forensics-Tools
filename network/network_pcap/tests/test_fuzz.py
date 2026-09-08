"""Mutation-fuzz the pcap container reader and the layer decoder."""

from __future__ import annotations

import pytest

from network_pcap import fuzzlib, layers, pcap

import _synth as s


def _seeds():
    pk = [(1.0, s.frame_udp("10.0.0.1", "10.0.0.2", 1000, 53,
                            s.dns_query("example.com")))]
    return [s.pcap(pk), s.pcap(pk, nano=True), s.pcapng(pk)]


def test_fuzz_pcap_reader(tmp_path):
    fuzzlib.fuzz(lambda p: list(pcap.read(p)), _seeds(),
                 iterations=500, seed=1, accepts="path", tmp_path=tmp_path,
                 allowed=fuzzlib.DEFAULT_ALLOWED + (pcap.PcapError,))


def test_fuzz_layer_decoder():
    frame = s.frame_tcp("10.0.0.1", "10.0.0.2", 12345, 80, b"GET / HTTP/1.1\r\n")
    frame6 = s.frame6_tcp("fd00::1", "fd00::2", 5, 5, b"x")
    fuzzlib.fuzz(lambda b: layers.decode(0.0, 1, b), [frame, frame6],
                 iterations=800, seed=2)
