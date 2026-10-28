#!/usr/bin/env python3
"""Test wireless analysis against real radiotap frames in the Wireshark GUI."""
import argparse
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading

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
        (2000000, new, 0x0108, 0, payload),  # unicast RA, broadcast DA
        (2100000, new, 0x0108, 0, payload),  # unicast RA, multicast DA
    ]
    with path.open('wb') as f:
        f.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 127))
        for seq, (us, ap, fc, flags, data) in enumerate(frames):
            radio = struct.pack('<BBHIBBHb', 0, 0, 15, 0x2e, flags, 108,
                                2412 if ap == old else 5180, -50 if ap == old else -65)
            # Channel flags belong between frequency and signal.
            radio = radio[:-1] + struct.pack('<H', 0xa0 if ap == old else 0x140) + radio[-1:]
            bssid_field = ap if (fc & 0xc) == 0 else server
            if seq == 10:
                bssid_field = bytes.fromhex('ffffffffffff')
            elif seq == 11:
                bssid_field = bytes.fromhex('01005e000001')
            packet = radio + struct.pack('<HH', fc, 0) + ap + sta + bssid_field + struct.pack('<H', seq << 4) + data
            f.write(struct.pack('<IIII', 1700000000 + us // 1000000, us % 1000000, len(packet), len(packet)))
            f.write(packet)


def records(path):
    data = path.read_bytes()
    offset = 24
    result = []
    while offset < len(data):
        seconds, micros, size, _ = struct.unpack_from('<IIII', data, offset)
        result.append((seconds * 1000000 + micros, data[offset + 16:offset + 16 + size]))
        offset += 16 + size
    return result


def write_variants(folder, capture):
    packets = records(capture)
    def block(kind, body):
        return struct.pack('<II', kind, len(body) + 12) + body + struct.pack('<I', len(body) + 12)
    # Two pcapng interfaces, with timestamps out of record order. Both APs have
    # the same channel number in different bands (channel 1, 2412 / 5955 MHz).
    data = block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
    data += block(1, struct.pack('<HHI', 127, 0, 65535)) * 2
    for index in (0, 7, 1, 8, 9):
        stamp, packet = packets[index]
        interface = int(index in (7, 8))
        if interface:
            packet = packet[:10] + struct.pack('<H', 5955) + packet[12:]
        body = struct.pack('<IIIII', interface, stamp >> 32, stamp & 0xffffffff, len(packet), len(packet))
        data += block(6, body + packet + b'\0' * (-len(packet) % 4))
    (folder / 'interfaces.pcapng').write_bytes(data)
    def pcap(name, linktype, values):
        with (folder / name).open('wb') as out:
            out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype))
            for stamp, packet in values:
                out.write(struct.pack('<IIII', stamp // 1000000, stamp % 1000000, len(packet), len(packet)))
                out.write(packet)
    pcap('missing-radio.pcap', 105, [(stamp, packet[15:]) for stamp, packet in packets[:2]])
    pcap('empty.pcap', 127, [])
    ethernet = udp_packet(socket.inet_aton('192.0.2.1'), socket.inet_aton('192.0.2.2'), 1234, 5678, b'not-wlan')
    pcap('ethernet.pcap', 1, [(1700000000000000, ethernet)])
    large = []
    stamp = 1700000000000000
    for index in range(502):
        stamp += index * 1000
        packet = packets[0][1]
        ap = (0x020000010000 + index).to_bytes(6, 'big')
        packet = packet[:19] + ap + packet[25:]
        large.append((stamp, packet))
    large.append((stamp + 1000, packet))
    pcap('pagination.pcap', 127, large)


def run_live(executable, capture, folder, env):
    pipe, control = folder / 'capture.pipe', folder / 'stage'
    os.mkfifo(pipe)
    packets = records(capture)
    def record(index):
        stamp, packet = packets[index]
        return struct.pack('<IIII', stamp // 1000000, stamp % 1000000, len(packet), len(packet)) + packet
    chunks = [b''.join(record(i) for i in range(2)),
              b''.join(record(i) for i in range(2, 9)),
              b''.join(record(i) for i in range(9, 12))]
    finished, errors = threading.Event(), []
    def feed():
        try:
            with pipe.open('wb', buffering=0) as stream:
                stream.write(capture.read_bytes()[:24] + chunks[0])
                stage = 0
                while not finished.wait(0.01):
                    request = control.read_text().strip() if control.exists() else ''
                    if request == 'stop':
                        break
                    if request == str(stage + 1):
                        stage += 1
                        stream.write(chunks[stage])
        except (BrokenPipeError, OSError) as error:
            if not finished.is_set():
                errors.append(str(error))
    writer = threading.Thread(target=feed, daemon=True)
    writer.start()
    env['WS_WIRELESS_LIVE_CONTROL'] = str(control)
    try:
        result = subprocess.run([str(executable), '-n', '-k', '-i', str(pipe)], env=env, timeout=120)
    finally:
        finished.set()
        writer.join(timeout=2)
    if errors:
        print(errors)
    return result.returncode or int(bool(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--screenshot-dir', type=Path)
    parser.add_argument('--language')
    parser.add_argument('--theme', choices=('light', 'dark'))
    parser.add_argument('--live', action='store_true', help='Also exercise real dumpcap pipe capture')
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
        write_variants(folder, capture)
        profile = folder / 'config'
        profile.mkdir()
        if args.language:
            (profile / 'language').write_text(f'ui_language.language: {args.language}\n')
        env = os.environ.copy()
        env['WIRESHARK_CONFIG_DIR'] = str(profile)
        env.setdefault('QT_QPA_PLATFORM', 'offscreen')
        env['WS_WIRELESS_FIXTURES'] = str(folder)
        if args.theme:
            env['WS_WIRELESS_THEME'] = args.theme
        if args.screenshot_dir:
            args.screenshot_dir.mkdir(parents=True, exist_ok=True)
            env['WS_WIRELESS_SCREENSHOTS'] = str(args.screenshot_dir.resolve())
        result = subprocess.run([str(executable), '-n', '-r', str(capture)], env=env, timeout=120).returncode
        if result or not args.live:
            return result
        return run_live(executable, capture, folder, env)


if __name__ == '__main__':
    raise SystemExit(main())
