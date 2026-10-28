#!/usr/bin/env python3
"""Exercise analysis snapshots and persistent bookmarks in three real GUI processes."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from run_follow_stream_filter_test import build_driver, write_fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, default=Path('build'))
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--screenshot-dir', type=Path)
    parser.add_argument('--language')
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    build = args.build_dir.resolve()
    output = build / 'analysis-session-test'
    output.mkdir(exist_ok=True)
    name = 'analysis_session_integration'
    if args.no_build:
        executable = next(p for p in (build / f'run/Wireshark.app/Contents/MacOS/{name}', build / f'run/{name}') if p.exists())
    else:
        executable = build_driver(source, build, output, 'test/qt/analysis_session_integration.cpp', name)
    with tempfile.TemporaryDirectory(prefix='analysis-', dir=output) as temporary:
        folder = Path(temporary)
        capture = folder / 'capture.pcap'
        write_fixture(capture, 0)
        shutil.copyfile(capture, folder / 'renamed.pcap')
        wrong = bytearray(capture.read_bytes())
        wrong[-1] ^= 1
        (folder / 'wrong.pcap').write_bytes(wrong)
        (folder / 'invalid.wsanalysis').write_text('{broken')
        profile = folder / 'config'
        profile.mkdir()
        if args.language:
            (profile / 'language').write_text(f'language: {args.language}\n')
        env = os.environ.copy()
        env.update(WIRESHARK_CONFIG_DIR=str(profile), WS_ANALYSIS_TEST_DIR=str(folder))
        env.setdefault('QT_QPA_PLATFORM', 'offscreen')
        for phase in ('write', 'read', 'import'):
            if phase == 'import':
                profile = folder / 'fresh-config'
                profile.mkdir()
                if args.language:
                    (profile / 'language').write_text(f'language: {args.language}\n')
                env['WIRESHARK_CONFIG_DIR'] = str(profile)
            env['WS_ANALYSIS_TEST_PHASE'] = phase
            if args.screenshot_dir:
                screenshots = args.screenshot_dir.resolve()
                screenshots.mkdir(parents=True, exist_ok=True)
                env['WS_ANALYSIS_SCREENSHOT'] = str(screenshots / f'analysis-{phase}.png')
            result = subprocess.run([str(executable), '-n', '-r', str(capture)], env=env, timeout=120)
            print(f'Analysis session {phase}: exit {result.returncode}', flush=True)
            if result.returncode:
                return result.returncode
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
