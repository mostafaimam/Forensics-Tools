# browser_extensions

**Installed browser extensions from a disk image.** Reads the Chromium
family (`Preferences` / `Secure Preferences`) and Firefox
(`extensions.json`) and lists every extension: id, name, version, install
source, enabled state, install time, and the **host and API permissions**
it holds.

![`browser_extensions --gui`](docs/screenshot.png)

```
browser_extensions /mnt/evidence/Users --csv extensions.csv
browser_extensions /cases/img/Users --sideloaded-only
browser_extensions ./Preferences --min-risk high --json x.json
browser_extensions /mnt/img/Users --perm nativeMessaging --perm debugger
```

Plain JSON parsing - no third-party dependency. Cross-platform.

---

## Why it matters

A malicious extension is one of the quietest ways to persist on a host and
steal data: it survives a password reset, runs on every page, and reads
whatever the user types. `browser_extensions` surfaces the ones worth a
second look.

| flag | meaning |
|---|---|
| `sideloaded (...)` | installed from the registry, a local pref file, or the command line - **not the web store** |
| `unsigned add-on` / `unknown add-on` | Firefox add-on that AMO never reviewed - only possible via a policy install or an unbranded / dev build |
| `installed by policy` | pushed by an enterprise policy (legitimate, or an attacker with admin) |
| `developer / unpacked` | loaded unpacked from a folder (developer mode) |
| `can read/modify traffic on every site` | `webRequest` + `<all_urls>` |
| `debugger` / `nativeMessaging` / `management` / `proxy` | high-risk APIs (attach the debugger, talk to a native binary, control other extensions, reroute traffic) |
| `custom update URL` | updates from somewhere other than Google / Mozilla |
| `persistent background page` | always-running background context |
| `disabled: <reason>` | disabled by the browser for a corruption / signature / verification reason, not by the user |

Each extension gets a **risk** of `low` / `medium` / `high`. A web-store
extension with broad permissions (an ad blocker, a password manager) is
`medium` at most; `high` needs a sideload, an unsigned add-on, or a
dangerous API from an untrusted source. Google's and Mozilla's own
bundled components are recognised and not flagged.

---

## Output

`--csv` (UTF-8 BOM, formula-injection safe) / `--json` columns:
`risk`, `browser`, `profile`, `name`, `ext_id`, `version`, `enabled`,
`install_source`, `from_webstore`, `signed_state`, `install_time`,
`update_url`, `host_permissions`, `api_permissions`, `content_scripts`,
`background`, `notable`, `path`, `source_file`.

| filter | |
|---|---|
| `--browser NAME` | one browser |
| `--enabled-only` | |
| `--sideloaded-only` | not from the web store |
| `--notable-only` / `--min-risk` | |
| `--perm NAME` (repeatable) | holds this permission |
| `--grep REGEX` | match name / id / description |

Point it at a mounted image's `Users` / `home` directory, a profile
folder, or one `Preferences` / `extensions.json` file.

---

## Limitations (v0.1)

* **`Secure Preferences` MAC is not verified** - a tampered file is read
  as-is (and the discrepancy is itself an IoC worth noting manually).
* The Chromium `Extensions/<id>/<ver>/manifest.json` on-disk copies are
  not yet cross-checked against `Preferences` for a mismatch.
* Extension **content / code** is not analysed - this is an inventory and
  a permission review, not a scanner.
* Deleted / uninstalled extensions that left a folder behind are not
  carved yet.
