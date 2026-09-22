"""mobile_appcommon - a generic inspector for the binary blob formats
that turn up throughout a mobile extraction and other tools' output:
binary property lists (with NSKeyedArchiver unwrapping, shared with
`macos_plist` / `mobile_iosbackup`) and **schemaless protobuf** - many
Android/iOS apps cache data as raw Protocol Buffers with no `.proto`
schema shipped alongside it.

Protocol Buffers' wire format itself is a public, precisely specified
encoding (varint tags, LEB128 varints, length-delimited fields,
fixed32/fixed64) - decoding it needs no schema, only field *numbers*
and wire *types*, which are self-describing. What a schema normally
supplies - field *names* and *semantic* types (is this length-delimited
field a string, bytes, or a nested message?) - is inferred heuristically
here: high confidence on the wire-level structure, lower confidence on
the semantic guess for each field. See the README.

Originally specified as a "shared back end, not run directly" - reframed
as its own small CLI tool, since a generic blob inspector is something
an examiner points at an unknown value (a BLOB column, a LevelDB value,
a cache file) directly, the same way `utilities_hex` does for raw bytes.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
