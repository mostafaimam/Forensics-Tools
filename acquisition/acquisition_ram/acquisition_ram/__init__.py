"""acquisition_ram - live memory acquisition.

* **Linux** - reads physical RAM through ``/proc/kcore`` (the kernel's own
  ELF view of memory) guided by ``/proc/iomem``, and writes a **LiME**,
  **raw** (compact) or **padded** (physical-layout) dump, hashing every byte.
* **Windows / macOS** - no userland full-RAM primitive without a driver, so
  it collects the files that *contain* memory (page file, ``hiberfil.sys`` /
  ``sleepimage``, crash / kernel dumps), handling locked files and a
  ``--source`` root for a mounted image.

Every run writes an acquisition log and a JSON manifest.
"""

__version__ = "0.1.0"
