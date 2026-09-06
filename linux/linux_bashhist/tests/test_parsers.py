from datetime import datetime, timezone

from linux_bashhist.parsers import parse_bash, parse_fish, parse_plain, parse_zsh

UTC = timezone.utc


def test_bash_with_timestamps():
    e = list(parse_bash("#1707552000\nls -la\n#1707552060\nsudo reboot\n"))
    assert len(e) == 2
    assert e[0].command == "ls -la"
    assert e[0].timestamp == datetime(2024, 2, 10, 8, 0, 0, tzinfo=UTC)
    assert e[1].command == "sudo reboot"


def test_bash_plain_one_per_line():
    e = list(parse_bash("whoami\ncat /etc/passwd\n"))
    assert [x.command for x in e] == ["whoami", "cat /etc/passwd"]
    assert all(x.timestamp is None for x in e)


def test_bash_multiline_command_between_timestamps():
    e = list(parse_bash("#1707552000\nfor i in 1 2 3\ndo echo $i\ndone\n"))
    assert len(e) == 1
    assert e[0].command == "for i in 1 2 3\ndo echo $i\ndone"


def test_zsh_extended_and_continuation():
    e = list(parse_zsh(": 1707600000:0;cd /x\n: 1707600030:5;a \\\nb\n"))
    assert e[0].command == "cd /x"
    assert e[0].timestamp == datetime(2024, 2, 10, 21, 20, tzinfo=UTC)
    assert e[1].command == "a \nb"


def test_fish_history():
    e = list(parse_fish("- cmd: echo hi\n  when: 1707610000\n- cmd: ls\n"))
    assert e[0].command == "echo hi"
    assert e[0].timestamp == datetime(2024, 2, 11, 0, 6, 40, tzinfo=UTC)
    assert e[1].command == "ls" and e[1].timestamp is None


def test_plain():
    e = list(parse_plain("import os\nos.system('id')\n"))
    assert [x.command for x in e] == ["import os", "os.system('id')"]
