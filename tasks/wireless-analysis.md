# Wireless analysis windows

## Scope

Two independent, modeless windows under Wireless: Roaming Analyzer and Wireless
Health. Use native Qt widgets, palette, typography, and Wireshark window lifecycle.
Do not change WLAN Statistics or the existing graph implementation.

## Measurement contract

- Analyze the capture independently of the packet-list display filter. Each window
  owns its selection and time range; navigation must not silently change filters.
- A roaming event is an observed change of BSSID for a unicast infrastructure STA
  between non-retry, payload-carrying data frames. Exclude null data, WDS, group
  destinations, malformed/bad-FCS frames and EAPOL. This is observational evidence,
  not proof of a successful handoff or application downtime.
- Report the old AP's last eligible data frame and the new AP's first eligible
  data frame, both frame numbers, timestamps and their interval. Keep the complete
  history across range selections. Compute in timestamp order, with frame number
  breaking ties. Mark cross-interface events as requiring clock alignment.
- Retry percentage is retry-flagged captured management/data frames divided by
  captured management/data frames. It is not a packet-loss estimate. Signal is
  capture-location dBm, PHY rate is Mb/s, neither is inferred when absent.
- Group health by BSSID, STA or observed channel/frequency; don't merge identical
  channel numbers across frequency bands. The selected entity and shared range
  drive all three trends and the statistics table. Empty bins remain missing.
- Capture extraction is batched on the GUI thread using a private dissection
  context. No global full-tree setting or persistent changes to the capture.
  Pause while the capture is busy; close/reload invalidates navigation. Bound
  retained samples and explicitly report incomplete results.

## Delivery and verification

1. Pure analysis model with semantic tests (roaming exclusions, sorted timestamps,
   missing metadata, range boundaries, health denominators and bins).
2. Capture adapter verified with deterministic radiotap PCAP/PCAPNG fixtures.
3. Independent windows with entity selection, numeric and graphical range controls,
   synchronized trends, selected-event packet buttons, and native light/dark style.
4. Real Qt workflows: menu entry, selection, range linking, packet navigation,
   live append, multiple windows, close/reopen/reload, empty and non-WLAN input.
5. Chinese translations, user documentation, cross-platform CI, release packages
   and downloaded-artifact verification through the repository release process.

## Progress

- Baseline: clean main at 4a7f714, fetched origin; current local build is available.
- Core model committed as 66d4ec3; standalone semantic tests pass.
- Capture adapter and both windows implemented. Native integration fixture passes:
  radiotap metadata, exclusions, two handoffs (100 ms and 300 ms), menu windows,
  packet navigation, STA/range transfer, health grouping, shared range, reopen.
- Deterministic PCAPNG coverage verifies out-of-order timestamps, cross-interface
  transitions, and separate 2.4/6 GHz channel-1 groups. Raw 802.11, empty and
  Ethernet inputs retain unknown measurements without inventing radio data.
- GUI regressions verify real drag/wheel/double-click and numeric range controls,
  entity-specific plotted values, multiple independent windows, exact navigation
  behind a main display filter, refresh and source close/reopen.
- A real dumpcap pipe fixture verifies live append, fixed versus all-time ranges,
  closing one window while another continues, stop and retained snapshots.
  An unchanged time field losing focus preserves all-time tracking; this defect
  was reproduced by observing collected roam events hidden by a frozen range.
- Review regressions exclude uplink broadcast/multicast destinations, preserve a
  selected STA during partial rescans, and sort globally before 500-row pagination.
  The latter two defects were first reproduced with failing GUI assertions.
- Numeric aggregation replaced per-packet string formatting: a local optimized
  2-million-sample benchmark measured 11 ms for health and 8 ms for trend aggregation.
  The sample boundary/incomplete-state/reset contract has a standalone regression.
- Chinese translations and user documentation cover both windows. The chart uses
  Wireshark graph theme colors; native macOS light/dark checks accompany the GUI
  regressions. Standalone Qt tests and the translation suite pass locally.
- CI includes wireless model tests on Windows/macOS/Linux and full native/live
  wireless integration on macOS. Terminal build results and downloaded-package
  verification are release gates; their evidence belongs to the GitHub release
  so the source commit can remain immutable.
- Local GUI test requires sandbox escalation on this Mac (otherwise process
  aborts before the Qt application starts). Command:
  `python3 test/qt/run_wireless_analysis_test.py --build-dir build`.
