# Windows item-view rendering regression

## Analysis sessions and persistent packet bookmarks

`analysis_session_test` runs with the standalone CMake/CTest project below.
It verifies strict JSON bounds, capture identity, atomic writes and locked merges.
After building Wireshark with Ninja, run:

```sh
python test/qt/run_analysis_session_test.py --build-dir build
QT_QPA_PLATFORM=cocoa python test/qt/run_analysis_session_test.py --build-dir build --no-build --language zh_CN --screenshot-dir build/analysis-session-ui
```

The integration driver runs two real GUI processes with an isolated profile.
It exercises the bookmark editor, Unicode notes/search, selection/filter/flag/column
restoration, hidden-packet navigation, moved/mismatched files, newer local edits,
deletions, read-filter isolation, and persistence across application restarts.
The driver is excluded from release packages.

## Item-view rendering

This standalone test builds the production `ThemeStyler` with Qt Widgets,
without a complete Wireshark build or a Qt Test dependency:

```sh
cmake -S test/qt -B build/packet-list-style-tests -DCMAKE_PREFIX_PATH=/path/to/Qt
cmake --build build/packet-list-style-tests --config Release
ctest --test-dir build/packet-list-style-tests -C Release --output-on-failure
```

The test renders real pixels for packet, frozen-column and pinned-row views;
Qt tree, table and list views/widgets; and protocol, expert-info and coloring-rule
view class identities. It exercises the Qt 6.8.3 Windows 11 border/inset geometry
through a small style fixture on every platform, and the real Windows 11 style
when available. Plain and alternating rows, explicit background colors,
active/inactive selection and hover states run at 100%, 125%, 150%, and 200%
pixel scales. Plain rows begin with the viewport base color; alternating rows
paint the row background before the delegate, matching the real view pipeline.

Packet-view focus outlines stay suppressed, including active/inactive stylesheet
selection colors with `outline: 0`. Ordinary views retain keyboard focus frames,
compared against Qt's independent common renderer with native metrics and focus
primitives. Real model/delegate checks cover coloring-rule backgrounds, editable
text and visible checkboxes. Button, header and checkbox-indicator rendering,
and all item rendering with other base styles, must retain their original pixels.

`QT_QPA_PLATFORM` defaults to `offscreen` unless explicitly set. On Windows 11,
set `QT_QPA_PLATFORM=windows` and `WS_REQUIRE_NATIVE_WINDOWS11_STYLE=1` to require
the native style check. A missing native style then fails the test rather than
silently skipping it.

# Follow Stream filtering integration regression

This regression requires a completed Ninja GUI build with GCC or Clang on macOS
or Linux. It reuses the generated
compile/link commands, replacing only the application entry object with a driver
that starts the real Wireshark application and invokes its normal Follow actions:

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build --target wireshark --parallel 3
python3 test/qt/run_follow_stream_filter_test.py --build-dir build
```

The runner generates a 14-packet Ethernet/IPv4 capture with two bidirectional TCP
streams and two bidirectional UDP streams, without extra Python dependencies. It
isolates settings with `WIRESHARK_CONFIG_DIR` and defaults Qt to `offscreen`.
Set `QT_QPA_PLATFORM=cocoa` or `xcb` to watch the real windows.

For each protocol it checks the applied capture filter, packet-list count and
exact reassembled payload after selected-packet Follow, changing streams,
reopening a stream while its filter is already applied, and following an explicit
conversation index. Each operation must produce exactly one completed Rescan and
no independent Retap, measured from real `CaptureFile::captureEvent` notifications.
Close must preserve the current filter without scanning; Back must restore the
original filter and packet count, including an empty filter that displays all
packets. An unrelated later retap must leave the completed
stream payload unchanged. Additional lifecycle checks close before the queued
filter runs and from inside a scan, change filters during a scan to force a
restart, cancel after a specific frame through a real tap, retry the same stream
after cancellation, open Follow during an already running rescan, and run an
existing Follow request during another scan without delivering its new filter
until that scan finishes. The latter test temporarily holds the public
`updateFilter` signal, then restores its normal connection and applies the saved
request through `filterPackets`, so progress UI cannot deliver it prematurely.
An unrelated retap also runs directly through the C API
while the Follow filter is pending. A frame tap delivers that queued filter while
the retap holds its read lock, including with the tiny fixture.
Queued filter actions are processed before assertions. Payload assertions inspect
the original rendered text without changing display controls, so they also catch
missing completion rendering. Completed controls must be enabled again.

To compare actual scan time, add a fixed amount of unrelated traffic while keeping
the followed streams small. Each Follow operation prints elapsed milliseconds as
well as real scan counts:

```sh
python3 test/qt/run_follow_stream_filter_test.py --build-dir build --background-packets 100000
```

The default 14-packet fixture tests correctness; its tiny runtimes are not a useful
measure of a performance improvement. Timing is diagnostic; scan counts and
functional results are the deterministic regression gates.

Before the optimization, Follow performs an independent Retap before applying
the main display filter. This deliberately fails the single-scan performance
requirement, including when the same stream filter is already applied.

After changing production code, rebuild `wireshark` and rerun the script so the
driver links the updated objects. `--no-build` only reruns an already linked driver.
The driver executable sits beside Wireshark inside the build output's app bundle
to reuse its resources and runtime paths. Remove this test executable before
packaging that output; it is not a product executable.

## Live Follow Stream

After building `wireshark` and `dumpcap` with Ninja on macOS or Linux:

```sh
python3 test/qt/run_follow_stream_live_test.py --build-dir build --limits
```

This starts real capture through a local FIFO and dumpcap, without accessing a
physical network interface or requiring capture privileges. The producer sends
deterministic TCP/UDP traffic in batches coordinated with the GUI driver.
Assertions cover incremental updates with no rescans, retransmission and
out-of-order handling, pause/resume, scroll and selection preservation, stream
switching, independent windows and encodings, split UTF-8 characters, filtering
and unrelated retaps, closure, capture EOF, and all formats compared with a fresh
offline Follow. `--limits` adds a 100,000-packet collector-limit check while the
main capture continues. `--language zh_CN --theme dark --screenshot-dir PATH`
records the localized UI; use `QT_QPA_PLATFORM=cocoa` for native macOS rendering.

The executable is `follow_stream_live_test` beside Wireshark in the build output;
remove it before packaging. The macOS CI does this with an EXIT trap.

## Packet comparison

The standalone target also tests typed-value matching independently of display
labels, parent paths, repeated scalar/container insertion, type changes, missing
fields, bounded large-repeat fallback, and linear offset byte differences:

```sh
cmake -S test/qt -B build/qt-tests -DCMAKE_PREFIX_PATH=/path/to/Qt6
cmake --build build/qt-tests
ctest --test-dir build/qt-tests --output-on-failure
```

After a full Ninja Wireshark build, run the real capture-file/Qt integration:

```sh
python3 test/qt/run_packet_comparison_test.py --build-dir build
```

The driver uses real pcap records and production packet-list actions, snapshots,
field trees and Hex widgets. It checks unchanged bytes in different frames,
changed TTL, VLAN insertion, capture truncation, reversible display options,
selection/filter stability, baseline selection, and reload/close lifetimes. The
isolated fixture/profile is saved beneath the build directory. Add
`--screenshot-dir build/comparison-screenshots` for rendered screenshots and
`--large-source` for two real 1 MiB USBPcap transfers. Comparison must not trigger
a full-file rescan or retap. On macOS,
remove `packet_comparison_integration` and `follow_stream_filter_test` from
`build/run/Wireshark.app/Contents/MacOS` before packaging; CI does this with traps.
