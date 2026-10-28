/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "ui/qt/utils/wireless_analysis.h"
#include <QCoreApplication>
#include <cmath>
#include <cstdio>

using namespace WirelessAnalysis;
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    int failures = 0;
    auto check = [&](bool result, const char *name) {
        fprintf(stderr, "%s: %s\n", result ? "PASS" : "FAIL", name);
        failures += !result;
    };
    Model model;
    Sample p;
    p.frame = 1; p.timeNs = 1000000000; p.sta = 0x020000000001;
    p.bssid = 0x020000000010; p.roamingEligible = true;
    p.retryEligible = true; p.frequency = 2412; p.channel = 1;
    p.signalDbm = -50; p.rateMbps = 54;
    model.append(p);
    p.frame = 2; p.timeNs += 50000000; model.append(p);
    const auto oldFrame = p.frame;
    p.frame = 3; p.timeNs += 20000000; p.bssid = 0x020000000020;
    p.roamingEligible = false; model.append(p); // Authentication/probe, not a roam.
    p.frame = 4; p.timeNs += 10000000; p.roamingEligible = true; p.retry = true;
    model.append(p);
    check(model.roaming().isEmpty(), "management and retries cannot trigger a roam");
    p.frame = 5; p.timeNs += 10000000; p.retry = false; p.interfaceId = 1;
    model.append(p);
    auto events = model.roaming();
    check(events.size() == 1 && events[0].oldFrame == oldFrame && events[0].newFrame == 5
          && events[0].gapNs() == 40000000 && events[0].crossInterface,
          "roam uses last old and first new data frames, preserving clock provenance");
    check(!model.append(p) && model.samples().size() == 5, "redissection does not duplicate frames");
    p.frame = 6; p.timeNs = 1030000000; p.bssid = 0x020000000010; model.append(p);
    check(model.roaming().size() == 1 && model.roaming()[0].oldFrame == 2,
          "capture-order timestamp reversal is analyzed in timestamp order");
    auto stats = model.health(Group::Station, {1000000000, 1090000000}).first();
    check(stats.packets == 6 && stats.retries == 1 && std::abs(*stats.retryPercent() - 100.0/6) < 1e-9,
          "retry percentage uses eligible captured frames in inclusive time range");
    check(*stats.signal() == -50 && *stats.rate() == 54, "known radio metadata aggregates correctly");
    p.frame = 7; p.timeNs = 2000000000; p.bssid = 0; p.sta = 0;
    p.roamingEligible = false; p.retryEligible = false;
    p.signalDbm.reset(); p.rateMbps.reset(); p.frequency = 5955;
    model.append(p);
    const auto channels = model.health(Group::Channel, model.extent());
    check(channels.size() == 2, "same channel number in two bands stays separate");
    const auto unknown = model.health(Group::Channel, {2000000000, 2000000000}).first();
    check(!unknown.signal() && !unknown.rate() && !unknown.retryPercent(),
          "missing radio metadata and absent retry denominator stay unknown");
    auto bins = model.trend(Group::Station, macString(0x020000000001), {0, 3000000000}, 3);
    check(bins.size() == 3 && bins[0].stats.packets == 0 && bins[1].stats.packets == 6
          && bins[2].stats.packets == 0 && !bins[0].stats.signal(), "empty trend bins are gaps, not zeros");
    bins = model.trend(Group::Station, macString(0x020000000001), {1000000000, 1090000000}, 2);
    check(bins[0].stats.packets + bins[1].stats.packets == 6, "right range endpoint belongs to last bin");
    check(model.health(Group::Station, {5, 4}).isEmpty(), "reversed ranges produce no statistics");
    model.clear();
    check(model.samples().isEmpty() && model.roaming().isEmpty(), "capture reset clears all state");
    return failures ? 1 : 0;
}
