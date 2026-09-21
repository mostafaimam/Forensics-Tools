"""Load rules, open a memory image, scan it, and shape rows for output."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from memory_yara.loader import MemoryImage, MemoryImageError
from memory_yara.rules import RuleSyntaxError, parse_rule, split_rules
from memory_yara.scanner import compile_rule, scan_stream

COLUMNS = ["rule", "description", "string_ids", "offsets", "notable",
          "source"]


@dataclass
class Result:
    rows: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def load_compiled_rules(rules_path: str) -> tuple[list, list[str]]:
    warnings = []
    text = Path(rules_path).read_text(encoding="utf-8", errors="replace")
    try:
        blocks = split_rules(text)
    except RuleSyntaxError as e:
        return [], [f"rule syntax error: {e}"]
    if not blocks:
        return [], [f"no rules found in {rules_path}"]
    compiled = []
    for name, body in blocks:
        try:
            compiled.append(compile_rule(parse_rule(name, body)))
        except RuleSyntaxError as e:
            warnings.append(f"rule {name!r}: {e}")
    if not compiled:
        warnings.append(f"no rule in {rules_path} parsed successfully")
    return compiled, warnings


def scan_image(image_path: str, rules_path: str) -> Result:
    res = Result()
    compiled, warnings = load_compiled_rules(rules_path)
    res.warnings.extend(warnings)
    if not compiled:
        return res
    try:
        with MemoryImage(image_path) as img:
            filesize = img.info().file_size
            hits = scan_stream(compiled, img.stream_runs(),
                              filesize=filesize)
    except (MemoryImageError, OSError) as e:
        res.warnings.append(f"{image_path}: {e}")
        return res

    for h in hits:
        offsets_str = "; ".join(
            f"{sid}@{','.join(hex(o) for o in offs[:5])}"
            for sid, offs in h.matched_strings.items())
        res.rows.append({
            "rule": h.rule_name,
            "description": h.meta.get("description", ""),
            "string_ids": ", ".join(sorted(h.matched_strings)),
            "offsets": offsets_str,
            "notable": h.meta.get("severity", "match"),
            "source": image_path,
        })
    if not res.rows:
        res.warnings.append("no rule matched anywhere in the image")
    return res
