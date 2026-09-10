r"""windows_usbdevices - reconstruct removable-device history.

Correlates, from the ``SYSTEM`` and ``SOFTWARE`` hives (and, when
present, ``setupapi.dev.log``):

* ``SYSTEM\...\Enum\USBSTOR`` - USB mass-storage device instances: the
  vendor / product / revision, the **serial number** (the instance id,
  with the connection-count suffix noted), the friendly name, and the
  per-device **install / first-install / last-arrival / last-removal**
  timestamps from the device ``Properties`` (FILETIME, UTC);
* ``SYSTEM\...\Enum\USB`` - the VID / PID and the container id;
* ``SYSTEM\MountedDevices`` - which **drive letter / volume** a device
  was mounted as (matched on the ``USBSTOR#`` string in the value data);
* ``SOFTWARE\...\Windows Portable Devices\Devices`` - the friendly volume
  name;
* ``setupapi.dev.log`` - the first-seen timestamp for each device from
  the ``Device Install`` blocks.

One row per device: vendor / product, serial, friendly name, drive
letter(s) / volume GUID, and the first-connected / last-connected /
last-removed times.  Flags devices connected only once, connected outside
business hours, and (with ``--known-good``) devices not on an allow-list.
Pure standard library (the ``regf`` parser is vendored); read-only.
"""

__version__ = "0.1.0"
