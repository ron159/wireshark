#!/usr/bin/env python3
"""Build and run the actual Qt Follow Stream workflow after a Ninja build.

No private production methods, source-text assertions, QtTest dependency, or
replacement capture implementation is used. All build flags and linked objects
come from Ninja's generated Wireshark commands.
"""

import argparse
import os
from pathlib import Path
import shlex
import socket
import struct
import subprocess
import sys


def command_segments(command):
    """Read CMake's `cd ... && compiler ... && :` commands without a shell."""
    tokens = shlex.split(command)
    segment = []
    for token in tokens + ["&&"]:
        if token == "&&":
            if segment:
                yield segment
            segment = []
        else:
            segment.append(token)


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff


def ethernet_ipv4(protocol, source, destination, payload):
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0,
                       64, protocol, 0, source, destination)
    ipv4 = ipv4[:10] + struct.pack("!H", checksum(ipv4)) + ipv4[12:]
    return bytes.fromhex("0200000000020200000000010800") + ipv4 + payload


def tcp_packet(source, destination, sport, dport, seq, ack, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 65535, 0, 0) + payload
    pseudo = source + destination + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    return ethernet_ipv4(6, source, destination, tcp)


def udp_packet(source, destination, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return ethernet_ipv4(17, source, destination, udp)


def write_fixture(path, background_packets=0):
    client = socket.inet_aton("192.0.2.1")
    server = socket.inet_aton("192.0.2.2")
    packets = []
    for stream in range(2):
        sport = 50000 + stream
        client_data = f"TCP-{stream}-CLIENT\n".encode()
        server_data = f"TCP-{stream}-SERVER\n".encode()
        packets.extend([
            tcp_packet(client, server, sport, 12345, 100, 0, 0x02),
            tcp_packet(server, client, 12345, sport, 200, 101, 0x12),
            tcp_packet(client, server, sport, 12345, 101, 201, 0x10),
            tcp_packet(client, server, sport, 12345, 101, 201, 0x18, client_data),
            tcp_packet(server, client, 12345, sport, 201, 101 + len(client_data), 0x18, server_data),
        ])
    for stream in range(2):
        sport = 51000 + stream
        packets.extend([
            udp_packet(client, server, sport, 12346, f"UDP-{stream}-CLIENT\n".encode()),
            udp_packet(server, client, 12346, sport, f"UDP-{stream}-SERVER\n".encode()),
        ])
    background = udp_packet(client, server, 52000, 12347, b"BACKGROUND\n")
    # Keep target stream IDs stable while adding unrelated traffic.
    if background_packets:
        packets = packets[:14] + [background] * background_packets
    with path.open("wb") as capture:
        capture.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, packet in enumerate(packets):
            capture.write(struct.pack("<IIII", 1700000000 + index, 0, len(packet), len(packet)))
            capture.write(packet)


def build_driver(source, build, output, test_source="test/qt/follow_stream_filter_test.cpp",
                 executable_name="follow_stream_filter_test"):
    commands = subprocess.check_output(
        ["ninja", "-C", str(build), "-t", "commands", "wireshark"], text=True)
    segments = [segment for line in commands.splitlines() for segment in command_segments(line)]
    compiles = [segment for segment in segments if "-c" in segment and
                any(token.endswith("/ui/qt/main.cpp") for token in segment)]
    links = [segment for segment in segments if "-o" in segment and "-c" not in segment and
             any(token.endswith("/main.cpp.o") for token in segment)]
    if len(compiles) != 1 or len(links) != 1:
        raise RuntimeError("Expected one main.cpp compile and one Wireshark link command from Ninja")
    compile_command = compiles[0][:]
    source_index = next(i for i, token in enumerate(compile_command) if token.endswith("/ui/qt/main.cpp"))
    compile_command[source_index] = str(source / test_source)
    object_path = output / f"{executable_name}.o"
    compile_command[compile_command.index("-o") + 1] = str(object_path)
    for flag in ("-MT", "-MF", "-MQ"):
        while flag in compile_command:
            index = compile_command.index(flag)
            del compile_command[index:index + 2]
    compile_command = [token for token in compile_command if token not in ("-MD", "-MMD")]
    subprocess.run(compile_command, cwd=build, check=True)

    link_command = links[0][:]
    executable = build / link_command[link_command.index("-o") + 1]
    executable = executable.with_name(executable_name)
    link_command[link_command.index("-o") + 1] = str(executable)
    main_object = next(i for i, token in enumerate(link_command) if token.endswith("/main.cpp.o"))
    link_command[main_object] = str(object_path)
    subprocess.run(link_command, cwd=build, check=True)
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=Path("build"))
    parser.add_argument("--no-build", action="store_true", help="Reuse the previously linked regression driver")
    parser.add_argument("--background-packets", type=int, default=0,
                        help="Append background UDP traffic, e.g. 100000 for a scan-time comparison")
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    build = args.build_dir.resolve()
    output = build / "follow-stream-filter-test"
    output.mkdir(parents=True, exist_ok=True)
    fixture = output / "two-tcp-two-udp.pcap"
    if args.background_packets < 0:
        parser.error("--background-packets must be nonnegative")
    write_fixture(fixture, args.background_packets)
    if args.no_build:
        candidates = [build / "run/Wireshark.app/Contents/MacOS/follow_stream_filter_test",
                      build / "run/follow_stream_filter_test"]
        executable = next(path for path in candidates if path.exists())
    else:
        executable = build_driver(source, build, output)
    failed = False
    for protocol, port in (("tcp", 50000), ("udp", 51000)):
        profile = output / f"config-{protocol}"
        profile.mkdir(exist_ok=True)
        env = os.environ.copy()
        env["WIRESHARK_CONFIG_DIR"] = str(profile)
        env["WS_FOLLOW_TEST_PROTOCOL"] = protocol
        env["WS_FOLLOW_TEST_BACKGROUND_PACKETS"] = str(args.background_packets)
        env.setdefault("QT_QPA_PLATFORM", "offscreen")
        print(f"Running {protocol.upper()} Follow Stream integration regression", flush=True)
        result = subprocess.run([str(executable), "-n", "-r", str(fixture), "-Y", f"{protocol}.srcport == {port}"],
                                env=env, timeout=90, check=False)
        print(f"{protocol.upper()} driver exit status: {result.returncode}", flush=True)
        failed |= result.returncode != 0
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
