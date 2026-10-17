#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify and ad-hoc sign the upstream application bundle before archiving it."""

import hashlib
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile


def run(*args):
    result = subprocess.run(args, text=True, capture_output=True)
    if result.returncode:
        print(result.stdout, file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        result.check_returncode()
    return result.stdout


app = Path(sys.argv[1]).resolve()
output = Path(sys.argv[2]).resolve()
frameworks = app / "Contents/Frameworks"
executables = app / "Contents/MacOS"
for required in (executables / "Wireshark", executables / "tshark",
                 frameworks / "QtCore.framework", frameworks / "QtSvg.framework",
                 app / "Contents/Resources/share/wireshark/coloring_rules.jsonc"):
    if not required.exists():
        raise SystemExit(f"Application bundle is missing {required}")
run("lipo", "-verify_arch", "arm64", str(executables / "Wireshark"))
(app / "Contents/Resources/qt.conf").write_text("[Paths]\nPlugins = PlugIns\n")

# Homebrew's split Qt prefixes can make osx-app.sh copy flattened Qt binaries
# before macdeployqt installs the complete frameworks. Only the latter are used.
for framework in frameworks.glob("Qt*.framework"):
    duplicate = frameworks / framework.stem
    if duplicate.is_file() and not duplicate.is_symlink():
        duplicate.unlink()

# Mach-O and universal-binary magic values, in either byte order.
magic_values = {bytes.fromhex(value) for value in (
    "feedface", "cefaedfe", "feedfacf", "cffaedfe",
    "cafebabe", "bebafeca", "cafebabf", "bfbafeca",
)}
native_files = []
for path in sorted(app.rglob("*")):
    if path.is_symlink() or not path.is_file():
        continue
    with path.open("rb") as stream:
        if stream.read(4) not in magic_values:
            continue
    native_files.append(path)
    identifiers = run("otool", "-D", str(path)).splitlines()[1:]
    for line in run("otool", "-L", str(path)).splitlines()[1:]:
        dependency = line.strip().split(" (compatibility version", 1)[0]
        if dependency in identifiers:
            continue
        if dependency.startswith("/") and not dependency.startswith(("/System/Library/", "/usr/lib/")):
            raise SystemExit(f"Unbundled library in {path}: {dependency}")
        if dependency.startswith("@rpath/") and not (frameworks / dependency[7:]).exists():
            raise SystemExit(f"Missing bundled library in {path}: {dependency}")

# Sign nested binaries first, followed by frameworks and the outer application.
for path in native_files:
    run("codesign", "--force", "--sign", "-", "--timestamp=none", str(path))
for path in sorted(frameworks.glob("*.framework")):
    run("codesign", "--force", "--sign", "-", "--timestamp=none", str(path))
run("codesign", "--force", "--sign", "-", "--timestamp=none", str(app))
run("codesign", "--verify", "--deep", "--strict", str(app))

output.mkdir(parents=True, exist_ok=True)
archive = output / "Wireshark-dynamic-macos-arm64.zip"
run("ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", str(app), str(archive))

# Test the extracted deliverable, including its Qt platform plugin and CLI data.
with tempfile.TemporaryDirectory(prefix="wireshark-package-") as temporary:
    run("ditto", "-x", "-k", str(archive), temporary)
    extracted = Path(temporary) / app.name
    run("codesign", "--verify", "--deep", "--strict", str(extracted))
    version = run(str(extracted / "Contents/MacOS/Wireshark"), "--version")
    capture = str(Path("test/captures/dhcp.pcap").resolve())
    tshark = str(extracted / "Contents/MacOS/tshark")
    run(tshark, "-G", "fields")
    frame = run(tshark, "-r", capture, "-c", "1",
                "-T", "fields", "-e", "frame.number").strip()
    if frame != "1":
        raise SystemExit(f"Packaged tshark returned an unexpected packet number: {frame!r}")
    config = Path(temporary) / "profile"
    config.mkdir()
    with subprocess.Popen(
        [str(extracted / "Contents/MacOS/Wireshark"), "-r", capture],
        cwd=temporary, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen", "WIRESHARK_CONFIG_DIR": str(config)},
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.communicate(timeout=15)
        else:
            raise SystemExit(f"Packaged GUI exited during startup ({process.returncode}):\n{stdout}\n{stderr}")

with archive.open("rb") as stream:
    digest = hashlib.file_digest(stream, "sha256").hexdigest()
(output / "SHA256SUMS").write_text(f"{digest}  {archive.name}\n")
with (app / "Contents/Info.plist").open("rb") as stream:
    minimum_macos = plistlib.load(stream)["LSMinimumSystemVersion"]
(output / "BUILD-INFO.txt").write_text(
    f"Commit: {os.environ.get('GITHUB_SHA', run('git', 'rev-parse', 'HEAD').strip())}\n"
    "OS: macOS\n"
    "Architecture: arm64 (Apple Silicon)\n"
    f"Minimum macOS version: {minimum_macos}\n"
    "Signing: ad-hoc; no Developer ID or Apple notarization\n\n"
    + version
)
print(f"Verified {len(native_files)} native files; packaged {archive.name} ({digest})")
