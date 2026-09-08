"""Mutation-fuzz the NetFlow / IPFIX / sFlow record reader."""

from __future__ import annotations

from network_flows import fuzzlib, records

import _synth as S


def _seeds():
    rec = [{"src": "10.0.0.5", "dst": "1.2.3.4", "dport": 443, "proto": 6,
            "octets": 5000, "pkts": 10}]
    return [
        S.nf5(rec),
        S.nf9(rec),
        S.nf9(rec, with_template=False),
        S.ipfix(rec),
        S.sflow([{"src": "10.0.0.5", "dst": "1.2.3.4"}]),
    ]


def test_fuzz_flow_reader(tmp_path):
    fuzzlib.fuzz(lambda p: list(records.read(p)), _seeds(),
                 iterations=600, seed=3, accepts="path", tmp_path=tmp_path,
                 allowed=fuzzlib.DEFAULT_ALLOWED + (records.FlowError,))
