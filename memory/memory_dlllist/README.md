# memory_dlllist

**Loaded modules per process from a Windows RAM dump.** Pool-tag scanning
for image / mapped-file VADs (`Vad`, `Vadl`). For each one the backing
file's full path is recovered by chasing
`_MMVAD → Subsection → ControlArea → FileObject → FileName` (newer Windows
10 builds also expose the `FileObject` directly), and the region is
attributed to a process by testing candidate directory-table bases.

![`memory_dlllist --gui`](docs/screenshot.png)

```
memory_dlllist MEMORY.DMP
memory_dlllist mem.lime --process powershell --csv mods.csv
memory_dlllist mem.raw --notable-only --json suspicious.json
memory_dlllist MEMORY.DMP --unbacked-only
```

No per-build symbol profile: the VPN pair (with its Win8.1+ high bytes)
sits at a stable node offset, and the pointer chain is offset-searched.
Reads raw / LiME / ELF-core / crash-dump images. Pure standard library,
cross-platform.

---

## Why it matters

* **The module list, from a dump** - which DLLs a process had mapped, at
  what base, from what path. The equivalent of `Process Explorer`'s lower
  pane, reconstructed from physical memory.
* **Load-path anomalies** - a DLL under `\Users\`, `\AppData\`, `\Temp\`,
  `\ProgramData\` or `\Downloads\` is not how Windows loads system code
  (`user-writable-path`). A `kernel32.dll` / `ntdll.dll` that is **not** in
  `\System32` / `\SysWOW64` / `\WinSxS` is a masquerade or a sideload
  (`system-dll-wrong-path`).
* **Manual maps & hollowing** - an executable image VAD with **no backing
  file** (`unbacked-image`) is a module that was mapped by hand rather than
  by the loader - reflective injection, or a section overwritten after
  load. Cross-check with `memory_malfind`.

---

## Flags

| flag | meaning |
|---|---|
| `unbacked-image` | executable image VAD, no file behind it |
| `user-writable-path` | loaded from a directory a normal user can write |
| `system-dll-wrong-path` | a known system DLL name outside the system directories |
| `no-directory` | a bare `name.dll` with no path component |

`--notable-only` keeps just the flagged rows; `--unbacked-only` keeps just
the manual maps. `confidence` is **high** for a flagged and attributed
module, **medium** for a resolved path, **low** when only the VAD geometry
survived.

---

## Output

Default is a per-process listing. `--csv` / `--json` give
`pid`, `process`, `base`, `size`, `name`, `path`, `protection`, `notable`,
`confidence`, `pool_tag`, `phys_offset`. CSV is UTF-8 with a BOM and
formula-injection safe.

---

## Limitations (v0.1)

* **Windows only.**
* It lists what is **mapped**, not what the loader's `InLoadOrderModuleList`
  says, so it does not directly diff for *unlinked* (hidden-from-`PEB`)
  modules - though an unlinked module still appears here as a normal row.
* The `_MMVAD` → file-name chain is offset-searched; an exotic build may
  leave a module `path` blank (it is still listed, at lower confidence).
* Not yet tested against a real multi-gigabyte dump - synthetic coverage
  only (a hand-built address space with a real `_SUBSECTION` /
  `_CONTROL_AREA` / `_FILE_OBJECT` / `_UNICODE_STRING` chain).
