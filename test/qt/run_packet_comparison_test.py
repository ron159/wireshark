#!/usr/bin/env python3
"""Run real packet-comparison dialogs, actions and capture-file lifecycle checks."""

import argparse
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys

from run_follow_stream_filter_test import build_driver, checksum, udp_packet


def write_comparison_fixture(folder):
    client = socket.inet_aton("192.0.2.1")
    server = socket.inet_aton("192.0.2.2")
    base = udp_packet(client, server, 52000, 12346, b"PAIR-CONTENT\n")
    ttl = bytearray(base)
    ttl[22] = 63
    ttl[24:26] = b"\0\0"
    ttl[24:26] = struct.pack("!H", checksum(bytes(ttl[14:34])))
    ttl = bytes(ttl)
    vlan = base[:12] + bytes.fromhex("810000640800") + base[14:]
    truncated = base[:-5]
    changed_port = udp_packet(client, server, 52000, 12347, b"PAIR-CONTENT\n")
    for name, content in (("base", base), ("ttl", ttl), ("vlan", vlan), ("truncated", truncated)):
        (folder / f"{name}.bin").write_bytes(content)
    records = [(base, len(base)), (base, len(base)), (ttl, len(ttl)),
               (vlan, len(vlan)), (truncated, len(base)), (changed_port, len(changed_port))]
    path = folder / "packet-comparison.pcap"
    with path.open("wb") as capture:
        capture.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, (content, reported_length) in enumerate(records):
            capture.write(struct.pack("<IIII", 1700000000 + index, 0, len(content), reported_length))
            capture.write(content)
    return path


def write_large_fixture(folder):
    # USBPcap permits large transfer records; Ethernet pcap records are limited
    # to 256 KiB by Wiretap, so a fabricated 1 MiB Ethernet packet is unsuitable.
    payload_length = 1024 * 1024
    header = struct.pack("<HQIHBHHBBI", 27, 1, 0, 9, 1, 1, 1, 0x81, 3, payload_length)
    left = header + b"A" * payload_length
    right = header + b"B" * payload_length
    (folder / "large-left.bin").write_bytes(left)
    (folder / "large-right.bin").write_bytes(right)
    path = folder / "packet-comparison-large.pcap"
    with path.open("wb") as capture:
        capture.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, len(left), 249))
        for index, content in enumerate((left, right)):
            capture.write(struct.pack("<IIII", 1700000000 + index, 0, len(content), len(content)))
            capture.write(content)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--screenshot-dir", type=Path)
    parser.add_argument("--large-source", action="store_true", help="Also compare two real 1 MiB USBPcap transfers")
    parser.add_argument("--theme", choices=("light", "dark"))
    parser.add_argument("--language", help="Load a real application translation, e.g. zh_CN")
    parser.add_argument("--pcapng", action="store_true", help="Convert the six-packet fixture using the built TShark and test pcapng")
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    build = args.build_dir.resolve()
    output = build / "packet-comparison-integration"
    output.mkdir(parents=True, exist_ok=True)
    fixture = write_comparison_fixture(output)
    executable_name = "packet_comparison_integration"
    if args.no_build:
        candidates = [build / f"run/Wireshark.app/Contents/MacOS/{executable_name}",
                      build / f"run/{executable_name}"]
        executable = next(path for path in candidates if path.exists())
    else:
        executable = build_driver(source, build, output,
                                  "test/qt/packet_comparison_integration.cpp", executable_name)
    if args.pcapng:
        tshark = executable.with_name("tshark")
        if not tshark.exists():
            tshark = build / "run/tshark"
        pcapng = output / "packet-comparison.pcapng"
        subprocess.run([str(tshark), "-r", str(fixture), "-F", "pcapng", "-w", str(pcapng)], check=True)
        fixture = pcapng
    profile = output / ("config-pcapng" if args.pcapng else "config")
    profile.mkdir(exist_ok=True)
    env = os.environ.copy()
    env["WIRESHARK_CONFIG_DIR"] = str(profile)
    env["WS_PACKET_COMPARISON_FIXTURE_DIR"] = str(output)
    if args.theme:
        env["WS_PACKET_COMPARE_THEME"] = args.theme
    if args.language:
        env["WS_PACKET_COMPARE_LANGUAGE"] = args.language
    if args.screenshot_dir:
        screenshots = args.screenshot_dir.resolve()
        screenshots.mkdir(parents=True, exist_ok=True)
        env["WS_PACKET_COMPARE_SCREENSHOT_DIR"] = str(screenshots)
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    result = subprocess.run([str(executable), "-n", "-r", str(fixture), "-Y", "udp"],
                            env=env, timeout=90, check=False)
    print(f"Packet comparison integration exit status: {result.returncode}", flush=True)
    failed = result.returncode != 0
    if args.large_source:
        large_fixture = write_large_fixture(output)
        env["WS_PACKET_COMPARISON_LARGE_SOURCE"] = "1"
        result = subprocess.run([str(executable), "-n", "-r", str(large_fixture), "-Y", "frame"],
                                env=env, timeout=90, check=False)
        print(f"Large source comparison exit status: {result.returncode}", flush=True)
        failed |= result.returncode != 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
