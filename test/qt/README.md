# Windows item-view rendering regression

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
