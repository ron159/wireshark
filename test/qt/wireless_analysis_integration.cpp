/* SPDX-License-Identifier: GPL-2.0-or-later */
#define main wireshark_application_main
#include "ui/qt/main.cpp"
#undef main
#include "ui/qt/wireless_capture.h"
#include "ui/qt/wireless_analysis_dialog.h"
#include "ui/qt/widgets/wireless_trend.h"
#include <QComboBox>
#include <QDoubleSpinBox>
#include <QPushButton>
#include <QTreeWidget>
#include <QDir>
#include <QElapsedTimer>
#include <QTimer>
#include <functional>

namespace {
WiresharkMainWindow *window = nullptr;
QElapsedTimer startup;
int failures = 0;
void check(bool condition, const char *message)
{
    fprintf(stderr, "%s: %s\n", condition ? "PASS" : "FAIL", message);
    failures += !condition;
}
bool waitUntil(const std::function<bool()> &predicate)
{
    QElapsedTimer timer; timer.start();
    while (!predicate() && timer.elapsed() < 10000) {
        QCoreApplication::sendPostedEvents(nullptr, QEvent::MetaCall);
        QCoreApplication::processEvents(QEventLoop::AllEvents, 20);
    }
    return predicate();
}
void runChecks()
{
    WirelessCapture capture(*window->captureFile());
    check(waitUntil([&] { return capture.scanned() == capture.total(); }), "real capture analysis completes");
    const auto &model = capture.model();
    check(model.samples().size() == 10, "all radiotap WLAN frames extracted");
    const auto events = model.roaming();
    check(events.size() == 2, "probe, null, retry, bad FCS and EAPOL are excluded from roaming");
    if (events.size() == 2) {
        check(events[0].oldFrame == 2 && events[0].newFrame == 8 && events[0].gapNs() == 100000000,
              "actual decoded frames produce the 100 ms handoff gap");
        check(events[1].oldFrame == 9 && events[1].newFrame == 10 && events[1].gapNs() == 300000000,
              "STA history records return to the old BSSID");
    }
    const auto aps = model.health(WirelessAnalysis::Group::AccessPoint, model.extent());
    check(aps.size() == 2, "real BSSID addresses form two AP groups");
    if (aps.size() == 2) {
        check(aps.first().signal() == -50 && aps.last().signal() == -65 && aps.first().rate() == 54,
              "signed dBm and PHY rates survive native dissection");
        check(aps.first().packets == 3 && aps.last().packets == 7 && aps.last().retries == 1,
              "health counts retain all captured frames and retry flags");
    }
    check(model.health(WirelessAnalysis::Group::Channel, model.extent()).size() == 2,
          "radiotap channels separated by observed frequency");
    window->findChild<QAction *>("actionWirelessRoaming")->trigger();
    auto *roaming = window->findChild<WirelessAnalysisDialog *>("wirelessRoamingDialog");
    check(roaming && roaming->isWindow(), "Wireless menu opens an independent roaming window");
    if (!roaming) { QCoreApplication::exit(1); return; }
    auto *history = roaming->findChild<QTreeWidget *>("wirelessTable");
    check(waitUntil([&] { return history->topLevelItemCount() == 2; }), "roaming history renders two real transitions");
    if (history->topLevelItemCount() != 2) { QCoreApplication::exit(1); return; }
    history->setCurrentItem(history->topLevelItem(0));
    roaming->findChild<QPushButton *>("roamingOldPacket")->click();
    check(window->captureFile()->capFile()->current_frame->num == 2, "old-packet button navigates main packet list");
    roaming->findChild<QPushButton *>("roamingNewPacket")->click();
    check(window->captureFile()->capFile()->current_frame->num == 8, "new-packet button navigates main packet list");
    roaming->findChild<QPushButton *>("roamingHealth")->click();
    auto *health = window->findChild<WirelessAnalysisDialog *>("wirelessHealthDialog");
    check(health && health->isWindow(), "selected roam opens a separate station health window");
    if (!health) { QCoreApplication::exit(1); return; }
    auto *table = health->findChild<QTreeWidget *>("wirelessTable");
    check(waitUntil([&] { return table->topLevelItemCount() == 1; }), "health focuses on selected STA");
    check(health->findChild<QComboBox *>("wirelessGroup")->currentIndex() == 1
          && health->findChild<QDoubleSpinBox *>("wirelessRangeStart")->value() == 1
          && health->findChild<QDoubleSpinBox *>("wirelessRangeEnd")->value() == 1.1,
          "roam-to-health navigation preserves STA and data-gap time range");
    if (table->topLevelItemCount() == 1)
        check(table->topLevelItem(0)->text(1) == "7", "range-linked table includes both endpoints");
    health->findChild<QPushButton *>("wirelessAllTime")->click();
    check(table->topLevelItemCount() == 1 && table->topLevelItem(0)->text(1) == "10", "all-time control restores full statistics");
    auto *chart = health->findChild<WirelessTrend *>("wirelessTrend");
    chart->rangeSelected(1.2, 1.5);
    check(table->topLevelItemCount() == 1 && table->topLevelItem(0)->text(1) == "2",
          "graph time selection updates health table and shared range");
    health->findChild<QPushButton *>("wirelessAllTime")->click();
    health->findChild<QComboBox *>("wirelessGroup")->setCurrentIndex(2);
    check(table->topLevelItemCount() == 2, "channel grouping updates the native health table");
    const auto screenshots = qEnvironmentVariable("WS_WIRELESS_SCREENSHOTS");
    if (!screenshots.isEmpty()) {
        QCoreApplication::processEvents();
        check(roaming->grab().save(QDir(screenshots).filePath("roaming.png")), "roaming screenshot saved");
        check(health->grab().save(QDir(screenshots).filePath("health.png")), "health screenshot saved");
    }
    const auto filename = window->captureFile()->filePath();
    check(window->openCaptureFile(filename), "capture can reopen while wireless windows exist");
    check(!capture.sourceValid() && !roaming->findChild<QPushButton *>("roamingOldPacket")->isEnabled(),
          "reopening capture invalidates old snapshots and packet navigation");
    health->close(); roaming->close();
    fprintf(stderr, "WIRELESS RESULT: %d failure(s)\n", failures);
    QCoreApplication::exit(failures ? 1 : 0);
}
void waitForCapture()
{
    for (auto *widget : QApplication::topLevelWidgets()) {
        window = qobject_cast<WiresharkMainWindow *>(widget);
        if (window) break;
    }
    auto *cf = window ? window->captureFile()->capFile() : nullptr;
    if (cf && cf->count == 10 && !cf->read_lock) runChecks();
    else if (startup.elapsed() > 30000) { check(false, "capture ready within 30 seconds"); QCoreApplication::exit(1); }
    else QTimer::singleShot(50, waitForCapture);
}
void schedule() { startup.start(); QTimer::singleShot(0, waitForCapture); }
}
Q_COREAPP_STARTUP_FUNCTION(schedule)
int main(int argc, char **argv) { return wireshark_application_main(argc, argv); }
