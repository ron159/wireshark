/* Live capture integration regression. SPDX-License-Identifier: GPL-2.0-or-later */
#define main wireshark_application_main
#include "ui/qt/main.cpp"
#undef main

#include "ui/qt/follow_stream_dialog.h"
#include "ui/qt/utils/theme_manager.h"
#include <QCheckBox>
#include <QComboBox>
#include <QElapsedTimer>
#include <QFile>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPointer>
#include <QScrollBar>
#include <QTimer>
#include <functional>

namespace {
WiresharkMainWindow *window;
capture_file *capture;
int failures = 0, rescans = 0, retaps = 0;
QElapsedTimer startup;

void check(bool ok, const char *message)
{
    fprintf(stderr, "%s: %s\n", ok ? "PASS" : "FAIL", message);
    failures += !ok;
}

bool waitUntil(const std::function<bool()> &ready, int timeout = 10000)
{
    QElapsedTimer timer;
    timer.start();
    while (!ready() && timer.elapsed() < timeout) {
        QEventLoop loop;
        QTimer::singleShot(20, &loop, &QEventLoop::quit);
        loop.exec();
    }
    return ready();
}

void settle()
{
    QEventLoop loop;
    QTimer::singleShot(250, &loop, &QEventLoop::quit);
    loop.exec();
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
}

void feed(const QString &stage)
{
    QFile file(qEnvironmentVariable("WS_LIVE_CONTROL"));
    check(file.open(QIODevice::WriteOnly | QIODevice::Truncate), "capture feeder control opens");
    file.write(stage.toUtf8());
}

FollowStreamDialog *openStream(int proto, unsigned stream)
{
    QMetaObject::invokeMethod(window, "openFollowStreamDialog", Qt::DirectConnection,
                             Q_ARG(int, proto), Q_ARG(unsigned, stream), Q_ARG(unsigned, 0U), Q_ARG(bool, true));
    settle();
    const auto dialogs = window->findChildren<FollowStreamDialog *>();
    return dialogs.isEmpty() ? nullptr : dialogs.last();
}

void run()
{
    mainApp->loadLanguage(qEnvironmentVariable("WS_LIVE_LANGUAGE", "en"));
    ThemeManager::instance()->setMode(qEnvironmentVariable("WS_LIVE_THEME") == "dark" ?
            ThemeManager::ThemeMode::Dark : ThemeManager::ThemeMode::Light);
    const QString protocol = qEnvironmentVariable("WS_LIVE_PROTOCOL");
    const int proto = proto_get_id_by_filter_name(protocol.toUtf8().constData());
    recent.gui_follow_show = SHOW_ASCII;
    recent.gui_follow_delta = FOLLOW_DELTA_NONE;
    QObject::connect(window->captureFile(), &CaptureFile::captureEvent, window, [](CaptureEvent event) {
        if (event.eventType() == CaptureEvent::Started) {
            rescans += event.captureContext() == CaptureEvent::Rescan;
            retaps += event.captureContext() == CaptureEvent::Retap;
        }
    });
    check(capture->state == FILE_READ_IN_PROGRESS, "real dumpcap capture is in progress");
    auto *dialog = openStream(proto, 0);
    check(dialog != nullptr, "live Follow dialog opens");
    if (!dialog) { QCoreApplication::exit(1); return; }
    auto *text = dialog->findChild<QPlainTextEdit *>("teStreamContent");
    check(text && text->toPlainText().contains(protocol.toUpper() + "-0-CLIENT"), "initial stream is collected");
    check(rescans == 1 && retaps == 0, "initial Follow still uses exactly one scan");
    const int scans_before = rescans;
    if (qEnvironmentVariableIntValue("WS_LIVE_LIMIT_TEST")) {
        auto *pause = dialog->findChild<QCheckBox *>("pauseLiveCheckBox");
        auto *status = dialog->findChild<QLabel *>("liveStatusLabel");
        pause->setChecked(true);
        feed("1");
        check(waitUntil([&] { return capture->count >= 100034; }, 45000), "capture receives more than the live collection packet limit");
        check(waitUntil([&] { return status->text().contains("100,000"); }), "reaching the live limit is explicitly reported while paused");
        const unsigned previous = capture->count;
        feed("2");
        check(waitUntil([&] { return capture->count > previous; }), "main capture continues after the follow collector reaches its limit");
        check(rescans == scans_before && retaps == 0, "collection limit requires no additional scan");
        QMetaObject::invokeMethod(dialog, "reject", Qt::DirectConnection);
        feed("stop");
        waitUntil([] { return capture->state == FILE_READ_DONE; });
        settle();
        fprintf(stderr, "LIVE LIMIT RESULT: %d failure(s)\n", failures);
        QCoreApplication::exit(failures ? 1 : 0);
        return;
    }
    feed("1");
    check(waitUntil([&] { return text->toPlainText().contains("LIVE-REPLY"); }), "new packets append without reopening");
    check(text->toPlainText().count("LIVE-ONE") == 1 && !text->toPlainText().contains("OTHER-STREAM"),
          "retransmissions and unrelated streams do not duplicate or leak into output");
    check(rescans == scans_before && retaps == 0, "live updates perform no full scan or retap");

    auto *pause = dialog->findChild<QCheckBox *>("pauseLiveCheckBox");
    check(pause != nullptr, "pause control exists");
    if (pause) pause->setChecked(true);
    const QString frozen = text->toPlainText();
    const unsigned previous_count = capture->count;
    feed("2");
    check(waitUntil([&] { return capture->count > previous_count; }), "capture continues while display is paused");
    settle();
    if (pause) check(text->toPlainText() == frozen, "paused display remains stable");
    if (pause) pause->setChecked(false);
    check(waitUntil([&] { return text->toPlainText().contains("PAUSED-DATA"); }), "resume catches up without losing data");

    feed("3");
    check(waitUntil([&] { return text->toPlainText().contains("LINE-0249"); }), "burst appends through the final packet");
    check(text->verticalScrollBar()->value() == text->verticalScrollBar()->maximum(), "auto-scroll follows new data at the bottom");
    const QString screenshot_dir = qEnvironmentVariable("WS_LIVE_SCREENSHOT_DIR");
    if (!screenshot_dir.isEmpty()) {
        check(dialog->grab().save(screenshot_dir + "/live-" + protocol + ".png"), "live stream screenshot saved");
    }
    text->verticalScrollBar()->setValue(0);
    QTextCursor selection(text->document());
    selection.setPosition(0);
    selection.setPosition(5, QTextCursor::KeepAnchor);
    text->setTextCursor(selection);
    feed("4");
    check(waitUntil([&] { return text->toPlainText().contains("SCROLL-PRESERVED"); }), "appending continues while reading history");
    check(text->verticalScrollBar()->value() == 0 && text->textCursor().selectedText() == selection.selectedText(),
          "history scroll position and selection are preserved");

    const QString before_rescan = text->toPlainText();
    window->filterPackets("frame.number > 0");
    settle();
    check(text->toPlainText() == before_rescan, "changing the main filter rebuilds without duplicated data");
    window->captureFile()->retapPackets();
    settle();
    check(text->toPlainText() == before_rescan, "unrelated retap rebuilds without duplicated data");

    dialog->follow(true, 1, 0);
    settle();
    feed("5");
    check(waitUntil([&] { return text->toPlainText().contains("SWITCHED-STREAM"); }), "switching live streams receives the new stream");
    check(!text->toPlainText().contains("PAUSED-DATA"), "switching streams discards the old stream state");
    QPointer<FollowStreamDialog> closed(dialog);
    QMetaObject::invokeMethod(dialog, "reject", Qt::DirectConnection);
    settle();
    check(closed.isNull(), "closing a live window releases its listener and dialog");
    const unsigned before_close_batch = capture->count;
    feed("6");
    check(waitUntil([&] { return capture->count > before_close_batch; }), "capture receives data with the stream window closed");
    dialog = openStream(proto, 0);
    text = dialog->findChild<QPlainTextEdit *>("teStreamContent");
    check(text->toPlainText().contains("AFTER-CLOSE"), "reopened window includes traffic received after closing");

    auto *charset = dialog->findChild<QComboBox *>("cbCharset");
    charset->setCurrentIndex(charset->findText("UTF-8"));
    auto *other = openStream(proto, 0);
    auto *other_charset = other->findChild<QComboBox *>("cbCharset");
    other_charset->setCurrentIndex(other_charset->findData(SHOW_HEXDUMP));
    auto *other_text = other->findChild<QPlainTextEdit *>("teStreamContent");
    feed("7");
    check(waitUntil([&] { return text->toPlainText().contains("UTF8-OTHER-DIRECTION"); }), "second live window does not change the first window's encoding");
    check(!text->toPlainText().contains(QChar::ReplacementCharacter), "incomplete UTF-8 waits for the next packet");
    QTextCursor tail_selection(text->document());
    tail_selection.movePosition(QTextCursor::End);
    tail_selection.movePosition(QTextCursor::PreviousCharacter, QTextCursor::KeepAnchor, 5);
    text->setTextCursor(tail_selection);
    const QString tail_selected = tail_selection.selectedText();
    feed("8");
    check(waitUntil([&] { return text->toPlainText().contains(QString::fromUtf8("你好")); }), "UTF-8 decoder joins characters split across packets and capture batches");
    check(text->textCursor().selectedText() == tail_selected, "a selection touching the old tail does not absorb newly appended text");
    check(waitUntil([&] { return other_text->toPlainText().contains("e4 bd") && other_text->toPlainText().contains("a0 e5 a5 bd"); }),
          "second window independently appends Hex output");
    QMetaObject::invokeMethod(other, "reject", Qt::DirectConnection);
    settle();
    charset->setCurrentIndex(charset->findData(SHOW_ASCII));
    const int before_order = rescans;
    feed("9");
    check(waitUntil([&] { return text->toPlainText().contains("ORDERED-TAIL"); }), "out-of-order TCP segments are reassembled before appending");
    check(rescans == before_order, "reassembly does not trigger a new scan");
    auto *directions = dialog->findChild<QComboBox *>("cbDirections");
    directions->setCurrentIndex(1);
    settle();
    pause = dialog->findChild<QCheckBox *>("pauseLiveCheckBox");
    pause->setChecked(true);
    const unsigned before_final = capture->count;
    feed("10");
    check(waitUntil([&] { return capture->count >= before_final + 2; }), "final data arrives while display is paused");
    feed("stop");
    check(waitUntil([] { return capture->state == FILE_READ_DONE; }), "capture pipe EOF stops the real capture");
    settle();
    pause->setChecked(false);
    check(waitUntil([&] { return text->toPlainText().contains("DIRECTION-SERVER"); }), "resuming after capture stops drains the final records");
    check(!text->toPlainText().contains("DIRECTION-CLIENT"), "direction filter applies to live appended records");
    directions->setCurrentIndex(0);
    check(waitUntil([&] { return text->toPlainText().contains("DIRECTION-CLIENT"); }), "changing direction restores retained client data");
    check(text->toPlainText().contains("AFTER-CLOSE"), "stopping capture retains the final stream contents");
    auto *status = dialog->findChild<QLabel *>("liveStatusLabel");
    check(status && status->text() == QCoreApplication::translate("FollowStreamDialog", "Capture stopped"), "stopped status remains accurate after resuming the display");

    // Compare every display format with an independent, freshly followed
    // offline stream. Hex offsets, YAML headers and C array indices must agree.
    auto *offline = openStream(proto, 0);
    auto *offline_charset = offline->findChild<QComboBox *>("cbCharset");
    auto *offline_text = offline->findChild<QPlainTextEdit *>("teStreamContent");
    for (int mode : {SHOW_ASCII, SHOW_CARRAY, SHOW_EBCDIC, SHOW_HEXDUMP, SHOW_RAW, SHOW_CODEC, SHOW_YAML}) {
        charset->setCurrentIndex(charset->findData(mode));
        offline_charset->setCurrentIndex(offline_charset->findData(mode));
        check(waitUntil([&] { return text->toPlainText() == offline_text->toPlainText(); }),
              "live collected data matches a fresh offline Follow in the selected format");
    }
    QMetaObject::invokeMethod(offline, "reject", Qt::DirectConnection);
    settle();
    const QString snapshot = text->toPlainText();
    cf_close(capture);
    settle();
    check(text->toPlainText() == snapshot && status->text() == QCoreApplication::translate("FollowStreamDialog", "Capture file closed"), "closing the capture preserves a safe readable snapshot");
    QMetaObject::invokeMethod(dialog, "reject", Qt::DirectConnection);
    settle();
    fprintf(stderr, "LIVE FOLLOW RESULT (%s): %d failure(s)\n", qPrintable(protocol), failures);
    QCoreApplication::exit(failures ? 1 : 0);
}

void waitForCapture()
{
    for (QWidget *widget : QApplication::topLevelWidgets()) {
        if ((window = qobject_cast<WiresharkMainWindow *>(widget))) break;
    }
    capture = window ? window->captureFile()->capFile() : nullptr;
    if (capture && capture->count >= 14 && !capture->read_lock) run();
    else if (startup.elapsed() > 30000) {
        check(false, "live capture starts within 30 seconds");
        QCoreApplication::exit(1);
    } else QTimer::singleShot(50, waitForCapture);
}

void schedule() { startup.start(); QTimer::singleShot(0, waitForCapture); }
}
Q_COREAPP_STARTUP_FUNCTION(schedule)
int main(int argc, char **argv) { return wireshark_application_main(argc, argv); }
