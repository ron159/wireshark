/* SPDX-License-Identifier: GPL-2.0-or-later */
#define main wireshark_application_main
#include "ui/qt/main.cpp"
#undef main
#include "ui/qt/wireless_capture.h"
#include "ui/qt/wireless_analysis_dialog.h"
#include "ui/qt/widgets/wireless_trend.h"
#include "ui/qt/utils/theme_manager.h"
#include "ui/qt/packet_dialog.h"
#include <QComboBox>
#include <QDoubleSpinBox>
#include <QPushButton>
#include <QTreeWidget>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QLabel>
#include <QMouseEvent>
#include <QPointer>
#include <QSpinBox>
#include <QTimer>
#include <QToolTip>
#include <QWheelEvent>
#include <QWindow>
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
void mouse(QWidget *widget, QEvent::Type type, QPointF position, Qt::MouseButton button, Qt::MouseButtons buttons)
{
    QMouseEvent event(type, position, widget->mapToGlobal(position.toPoint()), button, buttons, Qt::NoModifier);
    QApplication::sendEvent(widget, &event);
}
void checkVariants()
{
    const QDir fixtures(qEnvironmentVariable("WS_WIRELESS_FIXTURES"));
    check(window->openCaptureFile(fixtures.filePath("pagination.pcap")), "large history fixture opens");
    {
        WirelessAnalysisDialog roaming(*window, *window->captureFile(), WirelessAnalysisDialog::View::Roaming);
        roaming.setAttribute(Qt::WA_DeleteOnClose, false); roaming.show();
        auto *table = roaming.findChild<QTreeWidget *>("wirelessTable");
        auto *page = roaming.findChild<QSpinBox *>("wirelessPage");
        check(waitUntil([&] { return page->maximum() == 2; }), "501 transitions are paginated");
        check(table->topLevelItemCount() == 500, "history renders at most 500 rows per page");
        table->sortByColumn(4, Qt::DescendingOrder);
        check(table->topLevelItem(0)->text(6) == "502", "largest gap sorts first across all pages");
        page->setValue(2);
        check(table->topLevelItemCount() == 1 && table->topLevelItem(0)->text(6) == "2",
              "second page contains the smallest globally sorted gap");
        WirelessAnalysisDialog health(*window, *window->captureFile(), WirelessAnalysisDialog::View::Health);
        health.setAttribute(Qt::WA_DeleteOnClose, false); health.show();
        auto *aps = health.findChild<QTreeWidget *>("wirelessTable");
        check(waitUntil([&] { return health.findChild<QSpinBox *>("wirelessPage")->maximum() == 2; }),
              "502 AP groups are paginated");
        aps->sortByColumn(1, Qt::DescendingOrder);
        check(aps->topLevelItem(0)->text(1) == "2" && aps->topLevelItem(0)->text(0) == "02:00:00:01:01:f5",
              "highest packet count sorts first across all AP pages");
    }
    check(window->openCaptureFile(fixtures.filePath("interfaces.pcapng")), "two-interface pcapng opens");
    {
        WirelessCapture capture(*window->captureFile());
        check(waitUntil([&] { return capture.scanned() == 5; }), "two-interface pcapng is scanned");
        const auto events = capture.model().roaming();
        check(events.size() == 2 && events[0].oldFrame == 3 && events[0].newFrame == 2
              && events[0].gapNs() == 100000000 && events[0].crossInterface && events[1].crossInterface,
              "timestamp ordering and cross-interface clock warning survive real pcapng dissection");
        const auto &samples = capture.model().samples();
        check(samples.size() == 5 && samples[0].channel == 1 && samples[1].channel == 1
              && capture.model().health(WirelessAnalysis::Group::Channel, capture.model().extent()).size() == 2,
              "channel 1 in 2.4 and 6 GHz remains two groups");
    }
    check(window->openCaptureFile(fixtures.filePath("missing-radio.pcap")), "raw 802.11 capture opens");
    {
        WirelessCapture capture(*window->captureFile());
        check(waitUntil([&] { return capture.scanned() == 2; }), "raw 802.11 capture is scanned");
        const auto stats = capture.model().health(WirelessAnalysis::Group::Channel, capture.model().extent());
        check(stats.size() == 1 && !stats.first().signal() && !stats.first().rate() && stats.first().packets == 2,
              "absent radio metadata stays unknown, with packets retained");
    }
    for (const auto &name : {"empty.pcap", "ethernet.pcap"}) {
        check(window->openCaptureFile(fixtures.filePath(name)), "empty or Ethernet capture opens");
        WirelessAnalysisDialog health(*window, *window->captureFile(), WirelessAnalysisDialog::View::Health);
        health.setAttribute(Qt::WA_DeleteOnClose, false); health.show();
        auto *source = health.findChild<WirelessCapture *>();
        check(waitUntil([&] { return source->scanned() == source->total(); }), "empty or Ethernet scan completes");
        check(source->model().samples().isEmpty() && health.findChild<QTreeWidget *>("wirelessTable")->topLevelItemCount() == 0,
              "empty and non-WLAN inputs produce no fabricated measurements");
    }
}
void feed(const char *stage)
{
    QFile control(qEnvironmentVariable("WS_WIRELESS_LIVE_CONTROL"));
    check(control.open(QIODevice::WriteOnly | QIODevice::Truncate), "live feeder control opens");
    control.write(stage);
}
struct LiveState {
    QPointer<WirelessAnalysisDialog> roaming, health;
    QElapsedTimer deadline;
    int stage = 0, rescans = 0, retaps = 0;
    QMetaObject::Connection connection;
} live;
void pollLive()
{
    auto *cf = window->captureFile()->capFile();
    auto *history = live.roaming->findChild<QTreeWidget *>("wirelessTable");
    bool ready = false;
    switch (live.stage) {
    case 0: ready = live.health->findChild<WirelessCapture *>()->model().samples().size() == 2; break;
    case 1: ready = cf->count == 9 && history->topLevelItemCount() == 1
                       && live.health->findChild<WirelessCapture *>()->model().samples().size() == 9; break;
    case 2: ready = live.health.isNull(); break;
    case 3: ready = cf->count == 12 && history->topLevelItemCount() == 2; break;
    case 4: ready = cf->state == FILE_READ_DONE; break;
    }
    if (!ready) {
        if (live.deadline.elapsed() > 10000) {
            fprintf(stderr, "Live stage %d timed out: %u capture packets, %d history rows\n",
                    live.stage, cf->count, history->topLevelItemCount());
            for (auto *dialog : {live.roaming.data(), live.health.data()}) {
                if (!dialog) continue;
                auto *source = dialog->findChild<WirelessCapture *>();
                fprintf(stderr, "  %s: valid=%d scanned=%u samples=%lld roams=%lld read_lock=%d error=%s\n",
                        qPrintable(dialog->objectName()), source->sourceValid(), source->scanned(),
                        static_cast<long long>(source->model().samples().size()),
                        static_cast<long long>(source->model().roaming().size()), cf->read_lock, qPrintable(source->error()));
            }
            check(false, "asynchronous live stage completes within 10 seconds");
            feed("stop");
            QObject::disconnect(live.connection);
            QCoreApplication::exit(1);
            return;
        }
        QTimer::singleShot(20, pollLive);
        return;
    }
    switch (live.stage) {
    case 0: {
        check(true, "initial live frames appear");
        // Losing focus without editing must preserve the automatic time range.
        live.roaming->findChild<QDoubleSpinBox *>("wirelessRangeEnd")->editingFinished();
        live.health->findChild<QDoubleSpinBox *>("wirelessRangeStart")->setValue(0);
        auto *end = live.health->findChild<QDoubleSpinBox *>("wirelessRangeEnd");
        end->setValue(0.8); end->editingFinished();
        feed("1");
        break;
    }
    case 1:
        check(true, "appended frames update health and add a roam");
        check(live.health->findChild<QDoubleSpinBox *>("wirelessRangeEnd")->value() == 0.8
              && live.roaming->findChild<QDoubleSpinBox *>("wirelessRangeEnd")->value() == 1.2,
              "manual range stays fixed while other window follows live extent");
        check(live.rescans == 0 && live.retaps == 0, "wireless collection does not trigger global rescans or retaps");
        live.health->close();
        break;
    case 2:
        check(true, "closing one live window releases its collector");
        feed("2");
        break;
    case 3:
        check(true, "capture and remaining roaming window continue after health closes");
        feed("stop");
        break;
    case 4:
        check(true, "dumpcap capture stops cleanly");
        history->setCurrentItem(history->topLevelItem(0));
        live.roaming->findChild<QPushButton *>("roamingNewPacket")->click();
        check(cf->current_frame && cf->current_frame->num == 8, "packet navigation works after live capture stops");
        cf_close(cf);
        check(history->topLevelItemCount() == 2
              && !live.roaming->findChild<QPushButton *>("roamingNewPacket")->isEnabled(),
              "closing capture retains live history and disables stale navigation");
        QObject::disconnect(live.connection);
        live.roaming->close();
        fprintf(stderr, "WIRELESS LIVE RESULT: %d failure(s)\n", failures);
        QCoreApplication::exit(failures ? 1 : 0);
        return;
    }
    ++live.stage;
    live.deadline.restart();
    QTimer::singleShot(20, pollLive);
}
void runLive()
{
    check(window->captureFile()->capFile()->state == FILE_READ_IN_PROGRESS, "real dumpcap capture is running");
    live.connection = QObject::connect(window->captureFile(), &CaptureFile::captureEvent, window, [](CaptureEvent e) {
        if (e.eventType() == CaptureEvent::Started) {
            live.rescans += e.captureContext() == CaptureEvent::Rescan;
            live.retaps += e.captureContext() == CaptureEvent::Retap;
        }
    });
    window->findChild<QAction *>("actionWirelessRoaming")->trigger();
    window->findChild<QAction *>("actionWirelessHealth")->trigger();
    live.roaming = window->findChild<WirelessAnalysisDialog *>("wirelessRoamingDialog");
    live.health = window->findChild<WirelessAnalysisDialog *>("wirelessHealthDialog");
    check(live.roaming && live.health, "both independent windows open during live capture");
    if (!live.roaming || !live.health) { QCoreApplication::exit(1); return; }
    // Return to the real application event loop between stages: Cocoa capture
    // socket notifications cannot reliably run inside nested test wait loops.
    live.deadline.start();
    QTimer::singleShot(20, pollLive);
}
void runChecks()
{
    const auto theme = qEnvironmentVariable("WS_WIRELESS_THEME");
    if (theme == "dark") ThemeManager::instance()->setMode(ThemeManager::ThemeMode::Dark);
    if (theme == "light") ThemeManager::instance()->setMode(ThemeManager::ThemeMode::Light);
    WirelessCapture capture(*window->captureFile());
    check(waitUntil([&] { return capture.scanned() == capture.total(); }), "real capture analysis completes");
    const auto &model = capture.model();
    check(model.samples().size() == 12, "all radiotap WLAN frames extracted");
    const auto events = model.roaming();
    check(events.size() == 2, "probe, null, retry, bad FCS, EAPOL and group destinations are excluded from roaming");
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
        check(aps.first().packets == 3 && aps.last().packets == 9 && aps.last().retries == 1,
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
    auto *station = roaming->findChild<QComboBox *>("roamingStation");
    station->setCurrentIndex(1);
    const auto selectedStation = station->currentData();
    auto *roamingSource = roaming->findChild<WirelessCapture *>();
    roamingSource->refresh();
    // Rebuild before the next scan batch, as happens when a target STA appears
    // late in a large capture being rescanned.
    roaming->findChild<QPushButton *>("wirelessAllTime")->click();
    check(station->currentData() == selectedStation, "STA selection survives an empty partial rescan");
    check(waitUntil([&] { return roamingSource->scanned() == 12 && history->topLevelItemCount() == 2; }),
          "selected STA history is restored after refresh");
    check(station->currentData() == selectedStation, "STA selection remains after rescan completes");
    history->setCurrentItem(history->topLevelItem(0));
    roaming->findChild<QPushButton *>("roamingOldPacket")->click();
    check(window->captureFile()->capFile()->current_frame->num == 2, "old-packet button navigates main packet list");
    roaming->findChild<QPushButton *>("roamingNewPacket")->click();
    check(window->captureFile()->capFile()->current_frame->num == 8, "new-packet button navigates main packet list");
    window->filterPackets("frame.number == 1");
    check(waitUntil([&] { return window->captureFile()->capFile()->displayed_count == 1; }), "main display filter applied");
    check(waitUntil([&] { return history->topLevelItemCount() == 2; }), "roaming analysis remains independent of main filter");
    history->setCurrentItem(history->topLevelItem(0));
    roaming->findChild<QPushButton *>("roamingNewPacket")->click();
    auto *hidden = window->findChild<PacketDialog *>("wirelessRelatedPacket");
    check(hidden && hidden->windowTitle().contains("8")
          && window->captureFile()->displayFilter() == "frame.number == 1",
          "hidden related frame opens exactly in packet details without changing main filter");
    if (hidden) hidden->close();
    window->filterPackets("");
    check(waitUntil([&] { return window->captureFile()->capFile()->displayed_count == 12; }), "main display filter cleared");
    check(waitUntil([&] { return history->topLevelItemCount() == 2; }), "roaming history restored after filter rescan");
    history->setCurrentItem(history->topLevelItem(0));
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
    check(table->topLevelItemCount() == 1 && table->topLevelItem(0)->text(1) == "12", "all-time control restores full statistics");
    auto *chart = health->findChild<WirelessTrend *>("wirelessTrend");
    chart->rangeSelected(1.2, 1.5);
    check(table->topLevelItemCount() == 1 && table->topLevelItem(0)->text(1) == "2",
          "graph time selection updates health table and shared range");
    health->findChild<QPushButton *>("wirelessAllTime")->click();
    const auto plotWidth = chart->width() - 96;
    const QPointF from(76 + plotWidth * 0.25, 55), to(76 + plotWidth * 0.75, 55);
    mouse(chart, QEvent::MouseButtonPress, from, Qt::LeftButton, Qt::LeftButton);
    mouse(chart, QEvent::MouseMove, to, Qt::NoButton, Qt::LeftButton);
    mouse(chart, QEvent::MouseButtonRelease, to, Qt::LeftButton, Qt::NoButton);
    auto *rangeStart = health->findChild<QDoubleSpinBox *>("wirelessRangeStart");
    auto *rangeEnd = health->findChild<QDoubleSpinBox *>("wirelessRangeEnd");
    check(qAbs(rangeStart->value() - 0.525) < 1e-8 && qAbs(rangeEnd->value() - 1.575) < 1e-8
          && table->topLevelItem(0)->text(1) == "9", "real mouse drag selects range and updates statistics");
    QWheelEvent wheel(to, chart->mapToGlobal(to.toPoint()), QPoint(), QPoint(0, 120), Qt::NoButton,
                      Qt::NoModifier, Qt::NoScrollPhase, false);
    QApplication::sendEvent(chart, &wheel);
    check(rangeEnd->value() - rangeStart->value() < 1.05, "mouse wheel zooms shared time range");
    mouse(chart, QEvent::MouseButtonDblClick, to, Qt::LeftButton, Qt::LeftButton);
    check(rangeStart->value() == 0 && rangeEnd->value() == 2.1, "double-click restores full capture extent");
    rangeStart->setValue(1.2); rangeEnd->setValue(1.5); rangeEnd->editingFinished();
    check(table->topLevelItem(0)->text(1) == "2", "keyboard-editable time fields update statistics");
    health->findChild<QPushButton *>("wirelessAllTime")->click();
    health->findChild<QComboBox *>("wirelessGroup")->setCurrentIndex(2);
    check(table->topLevelItemCount() == 2, "channel grouping updates the native health table");
    table->setCurrentItem(table->topLevelItem(0));
    mouse(chart, QEvent::MouseMove, QPointF(76 + (chart->width() - 96) / 240.0, 55), Qt::NoButton, Qt::NoButton);
    check(QToolTip::text().contains("-50.00") && QToolTip::text().contains("54.00"),
          "selecting an entity updates plotted measurements and hover values");
    table->setCurrentItem(table->topLevelItem(1));
    mouse(chart, QEvent::MouseMove, QPointF(76 + (chart->width() - 96) / 240.0, 55), Qt::NoButton, Qt::NoButton);
    check(!QToolTip::text().contains("-50.00") && !QToolTip::text().contains("54.00"),
          "selected channel does not inherit another channel's measurements");
    QToolTip::hideText();
    health->findChild<QPushButton *>("wirelessAllEntities")->click();
    window->findChild<QAction *>("actionWirelessHealth")->trigger();
    auto *secondHealth = window->findChildren<WirelessAnalysisDialog *>("wirelessHealthDialog").last();
    check(secondHealth != health, "a second health window has its own instance");
    if (secondHealth != health) {
        auto *secondTable = secondHealth->findChild<QTreeWidget *>("wirelessTable");
        check(waitUntil([&] { return secondTable->topLevelItemCount() == 2; }), "second health window independently scans capture");
        chart->rangeSelected(1.2, 1.5);
        check(secondHealth->findChild<QDoubleSpinBox *>("wirelessRangeStart")->value() == 0
              && secondHealth->findChild<QDoubleSpinBox *>("wirelessRangeEnd")->value() == 2.1,
              "changing one window's range leaves the other window unchanged");
        secondHealth->close();
    }
    health->findChild<QPushButton *>("wirelessAllTime")->click();
    const auto screenshots = qEnvironmentVariable("WS_WIRELESS_SCREENSHOTS");
    if (!screenshots.isEmpty()) {
        for (auto *dialog : {roaming, health}) {
            (dialog == roaming ? health : roaming)->hide();
            dialog->show(); dialog->raise();
            check(waitUntil([&] { return dialog->windowHandle() && dialog->windowHandle()->isExposed(); }),
                  "screenshot window is exposed");
            // Background CI processes cannot always take foreground focus on
            // macOS. Render all children instead of relying on a cached backing
            // store from an obscured native window.
            QPixmap pixels(dialog->size() * dialog->devicePixelRatioF());
            pixels.setDevicePixelRatio(dialog->devicePixelRatioF());
            pixels.fill(dialog->palette().window().color());
            dialog->render(&pixels);
            check(pixels.save(QDir(screenshots).filePath(dialog == roaming ? "roaming.png" : "health.png")),
                  "native wireless screenshot saved");
        }
        roaming->show();
    }
    const auto filename = window->captureFile()->filePath();
    check(window->openCaptureFile(filename), "capture can reopen while wireless windows exist");
    check(!capture.sourceValid() && !roaming->findChild<QPushButton *>("roamingOldPacket")->isEnabled(),
          "reopening capture invalidates old snapshots and packet navigation");
    health->close(); roaming->close();
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    checkVariants();
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
    const bool live = !qEnvironmentVariableIsEmpty("WS_WIRELESS_LIVE_CONTROL");
    if (cf && cf->count == (live ? 2U : 12U) && !cf->read_lock) {
        if (live) runLive(); else runChecks();
    }
    else if (startup.elapsed() > 30000) { check(false, "capture ready within 30 seconds"); QCoreApplication::exit(1); }
    else QTimer::singleShot(50, waitForCapture);
}
void schedule() { startup.start(); QTimer::singleShot(0, waitForCapture); }
}
Q_COREAPP_STARTUP_FUNCTION(schedule)
int main(int argc, char **argv) { return wireshark_application_main(argc, argv); }
