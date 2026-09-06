"""A small map of common jump-list Application IDs to application names.

The AppID is the hex prefix of an ``*.automaticDestinations-ms`` /
``*.customDestinations-ms`` file name.
"""

APP_IDS = {
    "1bc392b8e104a00e": "Remote Desktop",
    "5f7b5f1e01b83767": "Quick Access / Explorer",
    "9b9cdc69c1c24e2b": "Notepad (Windows 11)",
    "9d1f905ce5044aee": "Microsoft Edge",
    "12dc1ea8e34b5a6": "Windows Photo Viewer / Photos",
    "5c450709f7ae4396": "File Explorer",
    "adecfb853d77462a": "Microsoft Word 2010",
    "a7bd71699cd38d1c": "Microsoft Word 2013",
    "9639cce715ea6f00": "Microsoft Word 2016/365",
    "ca44f6dbb4e34 db": "Microsoft Excel 2016/365",
    "7e4dca80246863e3": "Control Panel",
    "918e0ecb43d17e23": "Paint (Windows 11)",
    "1d49b2a1e3b6e8f0": "PowerShell",
    "6e079c6f8756c81c": "Notepad++",
    "b8ff88e4a9d5dc8d": "Google Chrome",
    "b6a26bbe1a58c07c": "Firefox",
    "271e609288a9d1f5": "VLC media player",
    "d9c623d43a5b4b12": "Command Prompt",
    "a232d0c53b4d3d4b": "Windows Media Player",
    "2b53c4ddf37c93a1": "7-Zip",
    "47bc21a3b8bb5cea": "WordPad",
    "e36bdb7cfdb8bf81": "Adobe Reader",
    "0e5f30f47b9b1338": "Adobe Photoshop",
    "d64d36b238c843a3": "Microsoft PowerPoint",
    "969252ce11249fdd": "Microsoft PowerPoint 2016/365",
    "de5aa5378e1e63dc": "Wireshark",
    "afca42fd48c07a4c": "VS Code",
}


def lookup(app_id: str) -> str:
    return APP_IDS.get(app_id.lower().strip(), "")
