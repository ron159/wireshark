#!/usr/bin/env python3
"""Exercise the real dumpcap -> pipe capture -> Qt live Follow Stream path."""

import argparse
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import time

from run_follow_stream_filter_test import build_driver, tcp_packet, udp_packet, write_fixture


def batches(protocol, directory, limits=False):
    initial = directory / "initial.pcap"
    write_fixture(initial)
    header, records = initial.read_bytes()[:24], initial.read_bytes()[24:]
    client, server = socket.inet_aton("192.0.2.1"), socket.inet_aton("192.0.2.2")
    seq = [[114, 214], [114, 214]]  # Initial TCP payloads have 13 bytes.
    stamp = 1700000100

    def packet(stream, from_server, data):
        nonlocal stamp
        src, dst = (server, client) if from_server else (client, server)
        if protocol == "tcp":
            sport, dport = (12345, 50000 + stream) if from_server else (50000 + stream, 12345)
            value = tcp_packet(src, dst, sport, dport, seq[stream][from_server],
                               seq[stream][not from_server], 0x18, data)
            seq[stream][from_server] += len(data)
        else:
            sport, dport = (12346, 51000 + stream) if from_server else (51000 + stream, 12346)
            value = udp_packet(src, dst, sport, dport, data)
        stamp += 1
        return struct.pack("<IIII", stamp, 0, len(value), len(value)) + value

    if limits:
        return header, [records, b"".join(packet(0, False, b"x") for _ in range(100020)),
                        packet(0, True, b"AFTER-LIMIT\n")]
    one = packet(0, False, b"LIVE-ONE\n")
    first = one + packet(0, True, b"LIVE-REPLY\n") + packet(1, False, b"OTHER-STREAM\n")
    if protocol == "tcp":
        first += one  # A genuine retransmission must not appear twice.
    second = packet(0, False, b"PAUSED-DATA\n")
    third = b"".join(packet(0, True, f"LINE-{i:04d}\n".encode()) for i in range(250))
    fourth = packet(0, True, b"SCROLL-PRESERVED\n")
    fifth = packet(1, True, b"SWITCHED-STREAM\n")
    sixth = packet(0, False, b"AFTER-CLOSE\n")
    seventh = packet(0, False, b"\xe4\xbd") + packet(0, True, b"UTF8-OTHER-DIRECTION\n")
    eighth = packet(0, False, b"\xa0\xe5\xa5\xbd\n")
    # Late TCP segments arrive out of order and must still reconstruct exactly.
    early = packet(0, False, b"ORDERED-")
    late = packet(0, False, b"TAIL\n")
    ninth = late + early if protocol == "tcp" else early + late
    tenth = packet(0, False, b"DIRECTION-CLIENT\n") + packet(0, True, b"DIRECTION-SERVER\n")
    return header, [records, first, second, third, fourth, fifth, sixth, seventh, eighth, ninth, tenth]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--limits", action="store_true", help="Also exercise the 100,000-packet live collection limit")
    parser.add_argument("--language", default="")
    parser.add_argument("--theme", choices=("light", "dark"), default="light")
    parser.add_argument("--screenshot-dir", type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    build = args.build_dir.resolve()
    output = build / "follow-stream-live-test"
    output.mkdir(exist_ok=True)
    if args.no_build:
        executable = next(p for p in (build / "run/Wireshark.app/Contents/MacOS/follow_stream_live_test",
                                      build / "run/follow_stream_live_test") if p.exists())
    else:
        executable = build_driver(source, build, output, "test/qt/follow_stream_live_test.cpp",
                                  "follow_stream_live_test")
    failed = False
    scenarios = [("tcp", False), ("udp", False)]
    if args.limits:
        scenarios.append(("udp", True))
    for protocol, limits in scenarios:
        with tempfile.TemporaryDirectory(prefix="ws-live-") as temporary:
            directory = Path(temporary)
            pipe, control = directory / "capture.pipe", directory / "stage"
            os.mkfifo(pipe)
            header, chunks = batches(protocol, directory, limits)
            errors = []
            finished = threading.Event()

            def feed():
                try:
                    with pipe.open("wb", buffering=0) as capture:
                        def write_all(data):
                            view = memoryview(data)
                            while view:
                                view = view[capture.write(view):]
                        write_all(header + chunks[0])
                        stage = 0
                        while not finished.wait(0.01):
                            request = control.read_text() if control.exists() else ""
                            if request.strip() == "stop":
                                break
                            if request.strip() == str(stage + 1):
                                stage += 1
                                write_all(chunks[stage])
                except (BrokenPipeError, OSError) as error:
                    if not finished.is_set():
                        errors.append(str(error))

            writer = threading.Thread(target=feed, daemon=True)
            writer.start()
            env = os.environ.copy()
            env.update(WIRESHARK_CONFIG_DIR=str(directory), WS_LIVE_PROTOCOL=protocol,
                       WS_LIVE_CONTROL=str(control), WS_LIVE_LIMIT_TEST=str(int(limits)),
                       WS_LIVE_LANGUAGE=args.language, WS_LIVE_THEME=args.theme)
            if args.screenshot_dir:
                args.screenshot_dir.mkdir(parents=True, exist_ok=True)
                env["WS_LIVE_SCREENSHOT_DIR"] = str(args.screenshot_dir.resolve())
            env.setdefault("QT_QPA_PLATFORM", "offscreen")
            print(f"Running live {protocol.upper()} through dumpcap and a capture pipe", flush=True)
            try:
                result = subprocess.run([str(executable), "-n", "-k", "-i", str(pipe)],
                                        env=env, timeout=120, check=False)
                failed |= result.returncode != 0
            finally:
                finished.set()
                writer.join(timeout=2)
            if errors:
                print(errors, flush=True)
                failed = True
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
