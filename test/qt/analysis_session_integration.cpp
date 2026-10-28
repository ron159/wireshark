/* SPDX-License-Identifier: GPL-2.0-or-later */
#define main wireshark_application_main
#include "ui/qt/main.cpp"
#undef main
#include "ui/qt/analysis_session_controller.h"
#include "ui/qt/packet_list.h"
#include <QDialogButtonBox>
#include <QDockWidget>
#include <QElapsedTimer>
#include <QFile>
#include <QHeaderView>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTimer>
#include <QTreeWidget>
#include <functional>

namespace {
WiresharkMainWindow *window;
AnalysisSessionController *controller;
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

bool restore(const QString &path, const QString &capture = QString(), bool expected = true)
{
    bool done = false, success = false;
    auto connection = QObject::connect(controller, &AnalysisSessionController::restoreFinished, window, [&](bool ok) {
        done = true; success = ok;
    });
    const bool started = controller->openSession(path, capture);
    const bool finished = started && waitUntil([&]() { return done; });
    QObject::disconnect(connection);
    check(finished && success == expected, expected ? "session restore completes successfully" : "mismatched capture restore finishes with failure");
    return finished && success;
}

void runChecks()
{
    const QString folder = qEnvironmentVariable("WS_ANALYSIS_TEST_DIR");
    const QString capture = folder + "/capture.pcap";
    const QString snapshot = folder + "/saved.wsanalysis";
    auto *packets = window->findChild<PacketList *>();
    auto *tree = window->findChild<QTreeWidget *>("packetBookmarks");
    auto *dock = window->findChild<QDockWidget *>("packetBookmarksDock");
    check(packets && tree && dock, "real packet list and bookmark dock exist");
    if (!packets || !tree || !dock) { QCoreApplication::exit(1); return; }
    if (qEnvironmentVariable("WS_ANALYSIS_TEST_PHASE") == "write") {
        check(controller->bookmarks().isEmpty(), "new capture has no bookmarks");
        window->gotoFrame(4);
        bool edited = false;
        QTimer::singleShot(0, window, [&]() {
            auto *dialog = window->findChild<QDialog *>("packetBookmarkEditor");
            check(dialog, "normal menu action opens bookmark editor");
            if (!dialog) return;
            dialog->findChild<QLineEdit *>("bookmarkTitle")->setText(QString::fromUtf8("请求入口"));
            dialog->findChild<QPlainTextEdit *>("bookmarkNote")->setPlainText(QString::fromUtf8("故障排查\n第二行备注"));
            const QString screenshot = qEnvironmentVariable("WS_ANALYSIS_SCREENSHOT");
            if (!screenshot.isEmpty()) {
                QCoreApplication::processEvents();
                check(dialog->grab().save(QFileInfo(screenshot).dir().filePath("bookmark-editor.png")), "bookmark editor screenshot saved");
            }
            edited = true;
            dialog->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Save)->click();
        });
        window->findChild<QAction *>("actionAddPacketBookmark")->trigger();
        check(edited && controller->bookmarks().size() == 1 && controller->bookmarks()[0].frame == 4,
              "editing through the real UI persists the selected packet");
        check(controller->setBookmark(10, "Second stream", "server response"), "second packet bookmark saved");
        window->filterPackets("tcp.stream eq 0");
        check(waitUntil([&]() { return window->captureFile()->displayFilter() == "tcp.stream eq 0" && controller->isReady(); }),
              "real display filter completes");
        auto *cf = window->captureFile()->capFile();
        cf_mark_frame(cf, frame_data_sequence_find(cf->provider.frames, 2));
        cf_ignore_frame(cf, frame_data_sequence_find(cf->provider.frames, 3));
        frame_data_sequence_find(cf->provider.frames, 1)->ref_time = true;
        cf->ref_time_count = 1;
        cf_reftime_packets(cf);
        window->gotoFrame(4);
        packets->header()->resizeSection(1, 190);
        packets->header()->moveSection(packets->header()->visualIndex(2), 1);
        packets->setColumnHidden(3, true);
        const int column_width = packets->header()->sectionSize(2);
        const QString first_title = QString::fromUtf8(get_column_title(1));
        check(controller->saveSession(snapshot), "analysis session is saved through production API");
        check(!controller->saveSession(capture), "saving over capture is rejected");
        check(controller->setBookmark(4, QString::fromUtf8("请求入口"), QString::fromUtf8("故障排查\n更新后的备注")),
              "later bookmark note saved");
        check(controller->removeBookmark(10), "later bookmark deletion saved");
        packets->header()->moveSection(1, 2);
        packets->setColumnHidden(3, false);
        packets->header()->resizeSection(2, 120);
        restore(snapshot);
        cf = window->captureFile()->capFile();
        check(controller->bookmarks().size() == 1 && controller->bookmarks()[0].note.contains(QString::fromUtf8("更新后")),
              "old snapshot preserves newer local notes and deletions");
        check(cf && QString::fromUtf8(cf->dfilter) == "tcp.stream eq 0" && cf->current_frame && cf->current_frame->num == 4,
              "display filter and selected packet restored");
        check(cf && cf->marked_count == 1 && cf->ignored_count == 1 && cf->ref_time_count == 1
              && frame_data_sequence_find(cf->provider.frames, 2)->marked
              && frame_data_sequence_find(cf->provider.frames, 3)->ignored
              && frame_data_sequence_find(cf->provider.frames, 1)->ref_time,
              "marked, ignored and time-reference state restored");
        check(packets->header()->sectionSize(2) == column_width && packets->isColumnHidden(3)
              && QString::fromUtf8(get_column_title(1)) == first_title, "column width, order and visibility restored");
        check(controller->setBookmark(10, "Second stream", "server response"), "deleted bookmark can be explicitly recreated");
        controller->goToBookmark(10);
        check(waitUntil([&]() { auto *c = window->captureFile()->capFile(); return c && c->current_frame && c->current_frame->num == 10; }),
              "hidden bookmark becomes visible and selected");
        check(window->getFilter().contains("tcp.stream eq 0") && window->getFilter().contains("frame.number == 10"),
              "bookmark navigation retains original filter matches");
        auto *search = window->findChild<QLineEdit *>("bookmarkSearch");
        search->setText(QString::fromUtf8("故障"));
        check(tree->topLevelItemCount() == 2 && !tree->topLevelItem(0)->isHidden() && tree->topLevelItem(1)->isHidden(),
              "bookmark search matches Unicode notes");
        search->clear();
        auto *before = window->captureFile()->capFile();
        const QString previous_filter = window->getFilter();
        restore(snapshot, folder + "/wrong.pcap", false);
        check(window->captureFile()->capFile() == before && window->getFilter() == previous_filter,
              "hash mismatch leaves current capture and filter unchanged");
        restore(snapshot, folder + "/renamed.pcap");
        check(controller->bookmarks().size() == 2, "identical renamed capture reuses persistent bookmarks");
        check(window->openCaptureFile(capture, "tcp"), "capture opens with a read filter");
        check(waitUntil([&]() { return controller->isReady(); }) && controller->bookmarks().isEmpty(),
              "read filter uses separate bookmark frame namespace");
        check(window->openCaptureFile(capture), "original capture reopened");
        check(waitUntil([&]() { return controller->isReady(); }) && controller->bookmarks().size() == 2,
              "original bookmarks return after reopening without read filter");
        check(!controller->openSession(folder + "/invalid.wsanalysis"), "malformed session rejected before opening capture");
        bool cancelled = false;
        auto connection = QObject::connect(controller, &AnalysisSessionController::restoreFinished, window,
            [&](bool success) { cancelled = !success; });
        check(controller->openSession(snapshot), "asynchronous restore starts");
        check(window->openCaptureFile(folder + "/wrong.pcap"), "another capture can replace pending restore");
        check(waitUntil([&]() { return cancelled && controller->isReady(); }) && controller->bookmarks().isEmpty(),
              "switching files cancels stale restore without leaking bookmarks");
        QObject::disconnect(connection);
        restore(snapshot);
        const QString saved_capture = folder + "/saved-capture.pcapng";
        cf = window->captureFile()->capFile();
        check(cf_save_records(cf, qUtf8Printable(saved_capture), wtap_pcapng_file_type_subtype(),
                              cf->compression_type, false, false) == CF_WRITE_OK, "capture saved in a new format through the real save pipeline");
        check(waitUntil([&]() { return controller->isReady(); }) && controller->bookmarks().size() == 2,
              "bookmarks migrate after saving capture contents in a new format");
        check(window->openCaptureFile(saved_capture), "newly saved capture reopened");
        check(waitUntil([&]() { return controller->isReady(); }) && controller->bookmarks().size() == 2,
              "migrated bookmarks persist for the new capture identity");
        restore(snapshot);
    } else if (qEnvironmentVariable("WS_ANALYSIS_TEST_PHASE") == "read") {
        check(controller->bookmarks().size() == 2 && controller->bookmarks()[0].note.contains(QString::fromUtf8("更新后")),
              "fresh process restores persistent Unicode bookmarks");
        check(controller->removeBookmark(10), "bookmark deletion persisted in fresh process");
        check(window->openCaptureFile(capture), "capture reopened after deletion");
        check(waitUntil([&]() { return controller->isReady(); }) && controller->bookmarks().size() == 1,
              "deleted bookmark stays deleted after reload");
    } else {
        check(controller->bookmarks().isEmpty(), "fresh profile starts without local bookmarks");
        restore(snapshot);
        check(controller->bookmarks().size() == 2 && controller->bookmarks()[0].note.contains(QString::fromUtf8("第二行")),
              "portable session imports its bookmark copy into a fresh profile");
    }
    dock->show();
    const QString screenshot = qEnvironmentVariable("WS_ANALYSIS_SCREENSHOT");
    if (!screenshot.isEmpty()) {
        window->resize(1350, 850);
        QCoreApplication::processEvents();
        check(window->grab().save(screenshot), "native UI screenshot saved");
    }
    fprintf(stderr, "ANALYSIS SESSION RESULT: %d failure(s)\n", failures);
    QCoreApplication::exit(failures ? 1 : 0);
}

void waitForCapture()
{
    for (auto *widget : QApplication::topLevelWidgets()) {
        window = qobject_cast<WiresharkMainWindow *>(widget);
        if (window) break;
    }
    controller = window ? window->findChild<AnalysisSessionController *>() : nullptr;
    if (controller && controller->isReady()) runChecks();
    else if (startup.elapsed() > 30000) { check(false, "capture identity ready within 30 seconds"); QCoreApplication::exit(1); }
    else QTimer::singleShot(50, waitForCapture);
}
void schedule() { startup.start(); QTimer::singleShot(0, waitForCapture); }
}
Q_COREAPP_STARTUP_FUNCTION(schedule)
int main(int argc, char **argv) { return wireshark_application_main(argc, argv); }
