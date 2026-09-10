"""Synthetic SYSTEM + SOFTWARE hives and a setupapi log for the test-suite."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

from _hive_synth import HiveBuilder, ft

PROP_GUID = "{83da6326-97a6-4088-9453-a1923f573b29}"
SERIAL_KINGSTON = "0016123456ABCDEF&0"
SERIAL_SANDISK = "4C530001120607111150"
PREFIX_KINGSTON = "7&1a2b3c4d&0"


def _ftblob(dt):
    return struct.pack("<Q", ft(dt))


def build_system_hive() -> bytes:
    b = HiveBuilder()
    t = lambda *a: datetime(*a, tzinfo=timezone.utc)  # noqa: E731

    def props(install, first, arrival, removal):
        def pid_key(name, dt):
            return b.nk(name, values=1,
                        val_list=b.value_list([b.vk_bin("", _ftblob(dt))]))
        guid = b.nk(PROP_GUID, subkeys=4, sub_list=b.li([
            pid_key("0064", install), pid_key("0065", first),
            pid_key("0066", arrival), pid_key("0067", removal)]))
        return b.nk("Properties", subkeys=1, sub_list=b.li([guid]))

    # --- Kingston (synthetic serial) ---
    k_inst = b.nk(SERIAL_KINGSTON, subkeys=1,
                  sub_list=b.li([props(
                      t(2026, 3, 1, 14, 0), t(2026, 3, 1, 14, 0),
                      t(2026, 3, 1, 14, 5), t(2026, 3, 1, 14, 30))]),
                  values=3, val_list=b.value_list([
                      b.vk_sz("FriendlyName", "Kingston DataTraveler USB "
                              "Device"),
                      b.vk_sz("ParentIdPrefix", PREFIX_KINGSTON),
                      b.vk_sz("ContainerID", "{11111111-1111-1111-1111-"
                              "111111111111}")]))
    k_prod = b.nk("Disk&Ven_Kingston&Prod_DataTraveler&Rev_1.00",
                  subkeys=1, sub_list=b.li([k_inst]))

    # --- SanDisk (real serial), connected once, at night ---
    s_inst = b.nk(SERIAL_SANDISK, subkeys=1,
                  sub_list=b.li([props(
                      t(2026, 3, 4, 23, 40), t(2026, 3, 4, 23, 40),
                      t(2026, 3, 4, 23, 40), t(2026, 3, 4, 23, 55))]),
                  values=2, val_list=b.value_list([
                      b.vk_sz("FriendlyName", "SanDisk Cruzer USB Device"),
                      b.vk_sz("ContainerID", "{22222222-2222-2222-2222-"
                              "222222222222}")]))
    s_prod = b.nk("Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.26",
                  subkeys=1, sub_list=b.li([s_inst]))

    usbstor = b.nk("USBSTOR", subkeys=2, sub_list=b.li([k_prod, s_prod]))

    # USB VID/PID
    k_usb_inst = b.nk(SERIAL_KINGSTON, values=1, val_list=b.value_list(
        [b.vk_sz("ContainerID", "{11111111-1111-1111-1111-111111111111}")]))
    k_vp = b.nk("VID_0951&PID_1666", subkeys=1, sub_list=b.li([k_usb_inst]))
    usb = b.nk("USB", subkeys=1, sub_list=b.li([k_vp]))

    enum = b.nk("Enum", subkeys=2, sub_list=b.li([usbstor, usb]))
    ccs = b.nk("ControlSet001", subkeys=1, sub_list=b.li([enum]))

    # MountedDevices
    def md_val(name, target):
        return b.vk_bin(name, target.encode("utf-16-le"))
    md = b.nk("MountedDevices", values=3, val_list=b.value_list([
        md_val("\\DosDevices\\E:",
               f"\\??\\USBSTOR#Disk&Ven_Kingston&Prod_DataTraveler&Rev_1.00#"
               f"{SERIAL_KINGSTON}#{{53f56307-b6bf-11d0-94f2-00a0c91efb8b}}"),
        md_val("\\??\\Volume{aaaaaaaa-0000-0000-0000-000000000001}",
               f"_??_USBSTOR#Disk&Ven_SanDisk#{SERIAL_SANDISK}#"),
        md_val("\\DosDevices\\C:", b"DMIO:ID:" .decode("latin-1"))]))

    root = b.nk("ROOT", flags=0x2C, subkeys=2, sub_list=b.li([ccs, md]))
    return b.build(root)


def build_software_hive() -> bytes:
    b = HiveBuilder()
    dev1 = b.nk(f"SWD#WPDBUSENUM#_??_USBSTOR#Disk&Ven_Kingston&"
                f"Prod_DataTraveler#{SERIAL_KINGSTON}#", values=1,
                val_list=b.value_list([
                    b.vk_sz("FriendlyName", "KINGSTON (E:)")]))
    devs = b.nk("Devices", subkeys=1, sub_list=b.li([dev1]))
    wpd = b.nk("Windows Portable Devices", subkeys=1, sub_list=b.li([devs]))
    ms = b.nk("Microsoft", subkeys=1, sub_list=b.li([wpd]))
    root = b.nk("ROOT", flags=0x2C, subkeys=1, sub_list=b.li([ms]))
    return b.build(root)


SETUPAPI_LOG = f"""\
[Device Install Log]
      OS Version = 10.0.19045

>>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.26\\{SERIAL_SANDISK}&0]
>>>  Section start 2026/03/04 23:39:58.410
     cmd: C:\\Windows\\system32\\services.exe
     dvi: {{Build Driver List}} 23:39:58.420
<<<  Section end 2026/03/04 23:40:01.998
<<<  [Exit status: SUCCESS]

>>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_Kingston&Prod_DataTraveler&Rev_1.00\\{SERIAL_KINGSTON}]
>>>  Section start 2026/03/01 13:59:55.100
<<<  Section end 2026/03/01 14:00:03.220
<<<  [Exit status: SUCCESS]
"""
