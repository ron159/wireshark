# Packet-list rendering regression

This standalone test builds the production `ThemeStyler` with Qt Widgets,
without a complete Wireshark build or a Qt Test dependency:

```sh
cmake -S test/qt -B build/packet-list-style-tests -DCMAKE_PREFIX_PATH=/path/to/Qt
cmake --build build/packet-list-style-tests --config Release
ctest --test-dir build/packet-list-style-tests -C Release --output-on-failure
```

The test renders real pixels for packet, frozen-column and pinned-row views.
It exercises the Qt 6.8.3 Windows 11 border/inset geometry through a small
style fixture on every platform, and the real Windows 11 style when available.
It also checks active/inactive stylesheet selection colors, focused cells with
`outline: 0`, and preservation of ordinary tree views and other base styles.
Target backgrounds are rendered at 100%, 125%, 150%, and 200% pixel scales.

`QT_QPA_PLATFORM` defaults to `offscreen` unless explicitly set. On Windows 11,
set `QT_QPA_PLATFORM=windows` and `WS_REQUIRE_NATIVE_WINDOWS11_STYLE=1` to require
the native style check. A missing native style then fails the test rather than
silently skipping it.
