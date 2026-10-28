#!/usr/bin/env python3
"""Test wireless analysis against real radiotap frames in the Wireshark GUI."""
import argparse
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile

from run_follow_stream_filter_test import build_driver, udp_packet


def write_fixture(path):
    sta = bytes.fromhex('020000000001')
    old = bytes.fromhex('020000000010')
    new = bytes.fromhex('020000000020')
    server = bytes.fromhex('020000000099')
    payload = bytes.fromhex('aaaa030000000800') + udp_packet(
        socket.inet_aton('192.0.2.1'), socket.inet_aton('192.0.2.2'), 1234, 5678, b'wireless-test')[14:]
    # (time in us, AP, FC, radiotap flags, payload)
    frames = [
        (0, old, 0x0108, 0, payload),
        (1000000, old, 0x0108, 0, payload),
        (1010000, new, 0x0040, 0, b'\x00\x00'),  # probe request
        (1020000, new, 0x0148, 0, b''),  # null data
        (1030000, new, 0x0908, 0, payload),  # retry
        (1040000, new, 0x0108, 0x40, payload),  # bad FCS metadata
        (1050000, new, 0x0108, 0, bytes.fromhex('aaaa03000000888e02000000')),
        (1100000, new, 0x0108, 0, payload),  # first real data on new AP
        (1200000, new, 0x0108, 0, payload),
        (1500000, old, 0x0108, 0, payload),  # return to old AP
    ]
    with path.open('wb') as f:
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 127))
        for seq, (us, ap, fc, flags, data) in enumerate(frames):
            radio = struct.pack('<BBHIBBHb', 0, 0, 15, 0x2e, flags, 108,
                                2412 if ap == old else 5180, -50 if ap == old else -65)
            # Channel flags belong between frequency and signal.
            radio = radio[:-1] + struct.pack('<H', 0xa0 if ap == old else 0x140) + radio[-1:]
            bssid_field = ap if (fc & 0xc) == 0 else server
            packet = radio + struct.pack('<HH', fc, 0) + ap + sta + bssid_field + struct.pack('<H', seq << 4) + data
            f.write(struct.pack('<IIII', 1700000000 + us // 1000000, us % 1000000, len(packet), len(packet)))
            f.write(packet)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--screenshot-dir', type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    build = args.build_dir.resolve()
    output = build / 'wireless-analysis-test'
    output.mkdir(exist_ok=True)
    name = 'wireless_analysis_integration'
    if args.no_build:
        executable = next(p for p in (build / f'run/Wireshark.app/Contents/MacOS/{name}', build / f'run/{name}') if p.exists())
    else:
        executable = build_driver(source, build, output, 'test/qt/wireless_analysis_integration.cpp', name)
    with tempfile.TemporaryDirectory(prefix='wireless-', dir=output) as temp:
        folder = Path(temp)
        capture = folder / 'wireless.pcap'
        write_fixture(capture)
        profile = folder / 'config'
        profile.mkdir()
        env = os.environ.copy()
        env['WIRESHARK_CONFIG_DIR'] = str(profile)
        env.setdefault('QT_QPA_PLATFORM', 'offscreen')
        if args.screenshot_dir:
            args.screenshot_dir.mkdir(parents=True, exist_ok=True)
            env['WS_WIRELESS_SCREENSHOTS'] = str(args.screenshot_dir.resolve())
        return subprocess.run([str(executable), '-n', '-r', str(capture)], env=env, timeout=120).returncode


if __name__ == '__main__':
    raise SystemExit(main())
