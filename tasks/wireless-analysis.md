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
- Design and measurement contract recorded. Implementation in progress.
