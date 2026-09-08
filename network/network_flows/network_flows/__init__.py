"""network_flows - NetFlow v5 / v9, IPFIX and sFlow record reader.

Parses exported flow records into one normalised unidirectional flow
schema, rolls them up into conversations (canonical 5-tuple), and
produces top-talker / port / long-flow summaries with beaconing,
scan-fan-out and large-transfer flags.  Template handling for v9 / IPFIX;
sFlow flow samples with a raw packet header are decoded through the
shared link-layer decoder.  Pure standard library.
"""

__version__ = "0.1.0"
