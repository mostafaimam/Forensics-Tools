import plistlib

from macos_plist.nskeyedarchiver import unwrap

try:
    from plistlib import UID
except ImportError:
    UID = None


def _archive(objects, top=None):
    return {
        "$archiver": "NSKeyedArchiver", "$version": 100000,
        "$objects": ["$null", *objects],
        "$top": top or {"root": UID(1)},
    }


def test_nsarray():
    a = _archive([
        {"$class": UID(4), "NS.objects": [UID(2), UID(3)]},   # 1
        "first", "second",                                    # 2, 3
        {"$classname": "NSArray", "$classes": ["NSArray"]},   # 4
    ])
    assert unwrap(a) == ["first", "second"]


def test_nested_dict_and_string_class():
    a = _archive([
        {"$class": UID(5), "NS.keys": [UID(2)], "NS.objects": [UID(3)]},  # 1
        "path",                                                          # 2
        {"$class": UID(4), "NS.string": "/Applications/Mail.app"},       # 3
        {"$classname": "NSMutableString", "$classes": ["NSMutableString"]},  # 4
        {"$classname": "NSDictionary", "$classes": ["NSDictionary"]},    # 5
    ])
    assert unwrap(a) == {"path": "/Applications/Mail.app"}


def test_nsdata_and_uuid():
    import uuid
    u = uuid.uuid4()
    a = _archive([
        {"$class": UID(4), "NS.keys": [UID(2)], "NS.objects": [UID(3)]},
        "id",
        {"$class": UID(5), "NS.uuidbytes": u.bytes},
        {"$classname": "NSDictionary", "$classes": ["NSDictionary"]},
        {"$classname": "NSUUID", "$classes": ["NSUUID"]},
    ])
    # indices shifted: fix
    a = _archive([
        {"$class": UID(3), "NS.keys": [UID(4)], "NS.objects": [UID(5)]},  # 1
        {"$classname": "NSDictionary", "$classes": ["NSDictionary"]},     # 2 (unused)
        {"$classname": "NSDictionary", "$classes": ["NSDictionary"]},     # 3
        "id",                                                            # 4
        {"$class": UID(6), "NS.uuidbytes": u.bytes},                      # 5
        {"$classname": "NSUUID", "$classes": ["NSUUID"]},                 # 6
    ])
    assert unwrap(a) == {"id": str(u)}


def test_cycle_is_broken():
    a = _archive([
        {"$class": UID(3), "NS.keys": [UID(2)], "NS.objects": [UID(1)]},  # 1 -> itself
        "self",
        {"$classname": "NSDictionary", "$classes": ["NSDictionary"]},
    ])
    out = unwrap(a)
    assert out["self"] == {"$cycle": 1}


def test_top_without_root_key():
    a = _archive([
        "hello",
    ], top={"$0": UID(1)})
    assert unwrap(a) == {"$0": "hello"}
