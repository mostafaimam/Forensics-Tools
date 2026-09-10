r"""macos_bt - Bluetooth paired-device history.

Reads ``/Library/Preferences/com.apple.Bluetooth.plist`` (and the
per-host ``~/Library/Preferences/ByHost/com.apple.Bluetooth.*.plist``):

* ``DeviceCache`` - every device the Mac has *seen*, keyed by MAC
  address: the name, the vendor / product id, the manufacturer company
  id, the class of device (decoded to a device type), the battery
  percentage, and the ``LastNameUpdate`` / ``LastInquiryUpdate`` /
  ``LastServicesUpdate`` timestamps (Mac absolute time -> UTC);
* ``PairedDevices`` / ``HIDDevices`` - which of those are paired, and
  which are input devices (keyboards / mice).

One row per device with an ``is_paired`` / ``is_hid`` / ``device_type``
summary.  Flags paired **input devices** (a BT keyboard is a keystroke-
injection vector), devices with a generic name, audio devices (a covert
microphone), and devices seen only once by inquiry.  Pure standard
library (``plistlib``), read-only.
"""

__version__ = "0.1.0"
