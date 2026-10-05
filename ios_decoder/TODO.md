# ios_decoder — open items

Design principles: transparent · cautious · portable · robust.

## Label tile bodies in `report` (VMP4 container vs style-72 protobuf tile)

Two different tile bodies currently show as unmatched or raw:

1. **Real VMP4** (`gspe19-ssl.ls.apple.com/tile.vf`): not protobuf. After optional gunzip the
   body starts with the bytes `VMP4` (all 159 successful iPhone 8 responses do), followed by a
   little-endian section table. Detect with `gunzip(body)[:4] == b"VMP4"`.
   `is_smart_interface_selection_tile` (formerly `is_vmp4`) does not match these. Consider
   emitting a one-line label such as `// Apple VMP4 vector tile (not protobuf; not decoded)`
   instead of a raw dump.
2. **Style-72 protobuf tiles** (`gspe79-ssl.ls.apple.com/72/v2/72/{quadkey}`): protobuf that
   parses as `SmartInterfaceSelectionTile`. `vmp4.py`'s `is_smart_interface_selection_tile(bytes)`
   detects them (gzip-transparent; 25/25 recall and no false positives on the capture corpora) but it
   is not wired into the decode path. Consider adding an endpoint-table entry for this tile type
   instead of a label.

Detection and labelling only: neither body type has a recoverable `PBCodable` schema. The format
details are in the `vmp4.py` module docstring.

## FlatBuffers bodies

Some Siri `swallow` bodies (for example `GetCertificate` and `CreateSession`) carry FlatBuffers, not
protobuf. They are shown as a hex preview with an "appears to be FlatBuffers (heuristic, not decoded)"
hint. Decoding them would need Apple's schema, so it would be a separate feature.
