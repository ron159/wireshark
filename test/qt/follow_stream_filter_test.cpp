/*
 * Follow Stream integration regression, linked against the real GUI.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// Reuse the production initialization, dissectors, packet list and event loop.
// run_follow_stream_filter_test.py replaces only main.cpp.o at link time.
#define main wireshark_application_main
#include "ui/qt/main.cpp"
#undef main

#include "ui/qt/follow_stream_dialog.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSpinBox>
#include <QTimer>

namespace {

struct ScanCounts {
    int rescans_started = 0;
    int rescans_finished = 0;
    int retaps_started = 0;
    int retaps_finished = 0;
};

WiresharkMainWindow *window = nullptr;
capture_file *capture = nullptr;
ScanCounts scans;
int failures = 0;
qint64 last_follow_elapsed = 0;
QElapsedTimer startup_timer;

void check(bool condition, const QString &message)
{
    fprintf(stderr, "%s: %s\n", condition ? "PASS" : "FAIL", qPrintable(message));
    if (!condition) {
        failures++;
    }
}

// Filter actions are queued by MainWindow::filterPackets. Drain MetaCall before
// inspecting cfile or resetting counters, including between Close and reopen.
void settleEvents()
{
    for (int i = 0; i < 3; i++) {
        QCoreApplication::sendPostedEvents(nullptr, QEvent::MetaCall);
        QCoreApplication::processEvents(QEventLoop::AllEvents);
    }
}

void checkSingleScan(const QString &operation)
{
    fprintf(stderr, "FOLLOW TIMING: %s: %lld ms (%u capture packets)\n",
            qPrintable(operation), static_cast<long long>(last_follow_elapsed), capture->count);
    check(scans.rescans_started == 1 && scans.rescans_finished == 1 &&
          scans.retaps_started == 0 && scans.retaps_finished == 0,
          QStringLiteral("%1 uses one completed rescan and no independent retap "
                         "(rescan %2/%3, retap %4/%5)")
              .arg(operation).arg(scans.rescans_started).arg(scans.rescans_finished)
              .arg(scans.retaps_started).arg(scans.retaps_finished));
}

void checkPayload(FollowStreamDialog *dialog, const QString &protocol, int stream)
{
    if (!dialog) {
        check(false, QStringLiteral("Follow Stream dialog exists"));
        return;
    }

    auto *charset = dialog->findChild<QComboBox *>(QStringLiteral("cbCharset"));
    auto *delta = dialog->findChild<QComboBox *>(QStringLiteral("deltaComboBox"));
    auto *content = dialog->findChild<QPlainTextEdit *>(QStringLiteral("teStreamContent"));
    check(charset && delta && content, QStringLiteral("real stream display controls exist"));
    if (!charset || !delta || !content) {
        return;
    }
    auto *stream_control = dialog->findChild<QSpinBox *>(QStringLiteral("streamNumberSpinBox"));
    check(charset->isEnabled() && delta->isEnabled() && stream_control && !stream_control->isReadOnly(),
          QStringLiteral("completed stream restores display and stream controls"));
    check(charset->currentIndex() == 0 && delta->currentIndex() == 0,
          QStringLiteral("stream is shown as ASCII without timing metadata"));
    const QString prefix = protocol.toUpper() + QLatin1Char('-') + QString::number(stream);
    // ASCII Follow separates direction changes with an additional newline.
    const QString expected = prefix + QStringLiteral("-CLIENT\n\n") + prefix + QStringLiteral("-SERVER\n");
    check(content->toPlainText() == expected,
          QStringLiteral("%1 stream %2 payload has both directions exactly once").arg(protocol).arg(stream));
    if (content->toPlainText() != expected) {
        fprintf(stderr, "PAYLOAD: actual=%s expected=%s (UTF-8 hex)\n",
                content->toPlainText().toUtf8().toHex().constData(), expected.toUtf8().toHex().constData());
    }
}

void checkStream(FollowStreamDialog *dialog, const QString &protocol, int stream)
{
    const QString filter = protocol + QStringLiteral(".stream eq ") + QString::number(stream);
    check(window->getFilter() == filter && QString::fromUtf8(capture->dfilter) == filter,
          QStringLiteral("display filter entry and capture both equal %1").arg(filter));
    check(capture->displayed_count == (protocol == QStringLiteral("tcp") ? 5U : 2U),
          QStringLiteral("main packet list contains the complete %1 stream %2").arg(protocol).arg(stream));
    checkPayload(dialog, protocol, stream);
}

FollowStreamDialog *openSelected(int proto)
{
    QElapsedTimer timer;
    timer.start();
    check(QMetaObject::invokeMethod(window, "openFollowStreamDialog", Qt::DirectConnection,
                                   Q_ARG(int, proto)),
          QStringLiteral("normal selected-packet Follow action runs"));
    settleEvents();
    last_follow_elapsed = timer.elapsed();
    return window->findChild<FollowStreamDialog *>();
}

FollowStreamDialog *openIndex(int proto, unsigned stream)
{
    QElapsedTimer timer;
    timer.start();
    check(QMetaObject::invokeMethod(window, "openFollowStreamDialog", Qt::DirectConnection,
                                   Q_ARG(int, proto), Q_ARG(unsigned, stream),
                                   Q_ARG(unsigned, 0U), Q_ARG(bool, true)),
          QStringLiteral("normal conversation-index Follow action runs"));
    settleEvents();
    last_follow_elapsed = timer.elapsed();
    return window->findChild<FollowStreamDialog *>();
}

void closeDialog(FollowStreamDialog *dialog)
{
    QPointer<FollowStreamDialog> closed_dialog(dialog);
    auto *buttons = dialog ? dialog->findChild<QDialogButtonBox *>(QStringLiteral("buttonBox")) : nullptr;
    check(buttons && buttons->button(QDialogButtonBox::Close), QStringLiteral("Close button exists"));
    if (buttons && buttons->button(QDialogButtonBox::Close)) {
        buttons->button(QDialogButtonBox::Close)->click();
    }
    settleEvents();
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    check(closed_dialog.isNull(), QStringLiteral("closed dialog is released after pending events"));
}

FollowStreamDialog *openPending(int proto, unsigned stream)
{
    check(QMetaObject::invokeMethod(window, "openFollowStreamDialog", Qt::DirectConnection,
                                   Q_ARG(int, proto), Q_ARG(unsigned, stream),
                                   Q_ARG(unsigned, 0U), Q_ARG(bool, true)),
          QStringLiteral("Follow action queues its display-filter update"));
    return window->findChild<FollowStreamDialog *>();
}

struct CancelAtPacket {
    bool fired = false;
};

tap_packet_status cancelAtPacket(void *data, packet_info *info, epan_dissect_t *, const void *, tap_flags_t)
{
    auto *cancel = static_cast<CancelAtPacket *>(data);
    if (!cancel->fired && info->num >= 6) {
        cancel->fired = true;
        window->captureFile()->stopLoading();
    }
    return TAP_PACKET_DONT_REDRAW;
}

tap_packet_status pumpQueuedFilter(void *data, packet_info *, epan_dissect_t *, const void *, tap_flags_t)
{
    auto *fired = static_cast<bool *>(data);
    if (!*fired) {
        *fired = true;
        QCoreApplication::sendPostedEvents(window, QEvent::MetaCall);
    }
    return TAP_PACKET_DONT_REDRAW;
}

void runLifecycleChecks(int proto, const QString &protocol)
{
    // Click Close before delivering the filter action's queued MetaCall.
    FollowStreamDialog *dialog = openPending(proto, 1U);
    closeDialog(dialog);
    check(QString::fromUtf8(capture->dfilter) == protocol + QStringLiteral(".stream eq 1"),
          QStringLiteral("pending filter completes safely after immediate Close"));

    // Close from inside a real scan, where deleting the dialog immediately would
    // invalidate the capture-event callback currently on the stack.
    dialog = openPending(proto, 0U);
    QPointer<FollowStreamDialog> closing_dialog(dialog);
    bool closed_during_scan = false;
    auto close_connection = QObject::connect(window->captureFile(), &CaptureFile::captureEvent,
                                             window, [&](CaptureEvent event) {
        if (!closed_during_scan && event.captureContext() == CaptureEvent::Rescan &&
            event.eventType() == CaptureEvent::Started && closing_dialog) {
            closed_during_scan = true;
            auto *buttons = closing_dialog->findChild<QDialogButtonBox *>(QStringLiteral("buttonBox"));
            buttons->button(QDialogButtonBox::Close)->click();
        }
    });
    settleEvents();
    QObject::disconnect(close_connection);
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    check(closed_during_scan && closing_dialog.isNull() && !capture->read_lock,
          QStringLiteral("closing during rescan releases the dialog after scan completion"));

    // Apply a different filter while read_lock is held. The core aborts and
    // restarts the rescan, and the Follow listener must survive that first pass.
    scans = {};
    dialog = openPending(proto, 0U);
    bool restarted = false;
    const QString replacement_filter = protocol + QStringLiteral(".stream eq 1");
    auto restart_connection = QObject::connect(window->captureFile(), &CaptureFile::captureEvent,
                                               window, [&](CaptureEvent event) {
        if (!restarted && event.captureContext() == CaptureEvent::Rescan &&
            event.eventType() == CaptureEvent::Started) {
            restarted = true;
            window->filterPackets(replacement_filter);
            QCoreApplication::sendPostedEvents(window, QEvent::MetaCall);
        }
    });
    settleEvents();
    QObject::disconnect(restart_connection);
    check(restarted && scans.rescans_started == 2 && scans.rescans_finished == 2 &&
          QString::fromUtf8(capture->dfilter) == replacement_filter && !capture->read_lock,
          QStringLiteral("a real filter change restarts and completes the scan"));
    fprintf(stderr, "RESTART: injected=%d rescans=%d/%d filter=%s\n", restarted,
            scans.rescans_started, scans.rescans_finished, capture->dfilter);
    checkPayload(dialog, protocol, 0);
    closeDialog(dialog);

    // The new dialog misses the Started notification currently being emitted.
    // It must only balance lifecycle notifications that it actually received.
    bool opened_during_scan = false;
    FollowStreamDialog *new_dialog = nullptr;
    auto create_connection = QObject::connect(window->captureFile(), &CaptureFile::captureEvent,
                                              window, [&](CaptureEvent event) {
        if (!opened_during_scan && event.captureContext() == CaptureEvent::Rescan &&
            event.eventType() == CaptureEvent::Started) {
            opened_during_scan = true;
            new_dialog = openPending(proto, 1U);
            QCoreApplication::sendPostedEvents(window, QEvent::MetaCall);
        }
    });
    window->filterPackets(protocol + QStringLiteral(".stream eq 0"));
    settleEvents();
    QObject::disconnect(create_connection);
    check(opened_during_scan && new_dialog, QStringLiteral("Follow can be opened during an existing rescan"));
    checkStream(new_dialog, protocol, 1);

    // This dialog already receives the old scan's Started. A Follow request
    // made during that scan belongs to a newer generation and must wait for
    // its own scan, even if the old scan finishes with no queued restart yet.
    bool requested_during_scan = false;
    bool old_scan_finished = false;
    QString held_filter;
    bool held_force = false;
    int held_requests = 0;
    check(QObject::disconnect(new_dialog, &FollowStreamDialog::updateFilter,
                              window, &WiresharkMainWindow::filterPackets),
          QStringLiteral("temporarily hold the public Follow filter request"));
    auto hold_connection = QObject::connect(new_dialog, &FollowStreamDialog::updateFilter,
                                            window, [&](QString filter, bool force) {
        held_filter = filter;
        held_force = force;
        held_requests++;
    });
    const QString ordinary_filter = protocol + QStringLiteral(" && frame.number >= 1");
    auto generation_connection = QObject::connect(window->captureFile(), &CaptureFile::captureEvent,
                                                  window, [&](CaptureEvent event) {
        if (event.captureContext() != CaptureEvent::Rescan) {
            return;
        }
        if (!requested_during_scan && event.eventType() == CaptureEvent::Started) {
            requested_during_scan = true;
            auto *spin = new_dialog->findChild<QSpinBox *>(QStringLiteral("streamNumberSpinBox"));
            spin->setValue(0);
            // The public signal observer holds this request until the old
            // scan returns, even if its progress UI processes other events.
        } else if (requested_during_scan && !old_scan_finished &&
                   event.eventType() == CaptureEvent::Finished) {
            old_scan_finished = true;
            check(QString::fromUtf8(capture->dfilter) == ordinary_filter,
                  QStringLiteral("old scan finishes before the newer Follow filter is delivered"));
            // Deliver a prematurely scheduled render, but not the main window's
            // queued filter action. Correct code has no completed render yet.
            QCoreApplication::sendPostedEvents(new_dialog, QEvent::MetaCall);
            auto *charset = new_dialog->findChild<QComboBox *>(QStringLiteral("cbCharset"));
            check(charset && !charset->isEnabled(),
                  QStringLiteral("old scan cannot complete a newer Follow request"));
        }
    });
    window->filterPackets(ordinary_filter);
    settleEvents();
    QObject::disconnect(generation_connection);
    QObject::disconnect(hold_connection);
    QObject::connect(new_dialog, &FollowStreamDialog::updateFilter,
                     window, &WiresharkMainWindow::filterPackets);
    check(requested_during_scan && old_scan_finished,
          QStringLiteral("existing Follow requests a new stream during another scan"));
    check(held_requests == 1 && held_filter == protocol + QStringLiteral(".stream eq 0") && held_force,
          QStringLiteral("one complete Follow request was held at the public signal boundary"));
    window->filterPackets(held_filter, held_force);
    settleEvents();
    checkStream(new_dialog, protocol, 0);
    closeDialog(new_dialog);

    // A real frame tap requests cancellation after the sixth packet, avoiding
    // sleeps and progress-dialog timing. Retry the same filter afterwards.
    dialog = openPending(proto, 1U);
    CancelAtPacket cancel;
    GString *error = register_tap_listener("frame", &cancel, nullptr, 0, nullptr,
                                           cancelAtPacket, nullptr, nullptr);
    check(error == nullptr, QStringLiteral("cancellation observer attaches to real frame tap"));
    if (error) {
        g_string_free(error, TRUE);
    }
    settleEvents();
    if (!error) {
        remove_tap_listener(&cancel);
        auto *stream = dialog->findChild<QSpinBox *>(QStringLiteral("streamNumberSpinBox"));
        check(cancel.fired && capture->stop_flag && !capture->read_lock && stream && !stream->isReadOnly(),
              QStringLiteral("cancelled filtering finishes and restores stream controls"));
    }
    closeDialog(dialog);
    scans = {};
    dialog = openIndex(proto, 1U);
    checkStream(dialog, protocol, 1);
    checkSingleScan(QStringLiteral("retrying the same stream after cancellation"));
    closeDialog(dialog);

    // An unrelated retap may occur while the follow filter is still queued.
    // It must neither consume the listener nor strand a queued filter forever.
    dialog = openPending(proto, 0U);
    bool pumped_filter = false;
    error = register_tap_listener("frame", &pumped_filter, nullptr, 0, nullptr,
                                  pumpQueuedFilter, nullptr, nullptr);
    check(error == nullptr, QStringLiteral("pending filter observer attaches to real frame tap"));
    if (error) {
        g_string_free(error, TRUE);
    }
    cf_retap_packets(capture);
    if (!error) {
        remove_tap_listener(&pumped_filter);
        check(pumped_filter, QStringLiteral("queued filter is delivered while retap holds the read lock"));
    }
    settleEvents();
    checkStream(dialog, protocol, 0);
    check(capture->redissection_queued == RESCAN_NONE && !capture->read_lock,
          QStringLiteral("retap while Follow is pending leaves no stranded rescan"));
    closeDialog(dialog);
}

void runChecks()
{
    recent.gui_follow_show = SHOW_ASCII;
    recent.gui_follow_delta = FOLLOW_DELTA_NONE;
    const QString protocol = qEnvironmentVariable("WS_FOLLOW_TEST_PROTOCOL", "tcp");
    const int proto = proto_get_id_by_filter_name(protocol.toUtf8().constData());
    const QString previous_filter = window->getFilter();
    const uint32_t previous_count = capture->displayed_count;

    const unsigned background_packets = qEnvironmentVariableIntValue("WS_FOLLOW_TEST_BACKGROUND_PACKETS");
    check(proto >= 0 && capture->count == 14 + background_packets && capture->edt,
          QStringLiteral("deterministic TCP/UDP fixture loaded and packet selected"));
    QObject::connect(window->captureFile(), &CaptureFile::captureEvent, window, [](CaptureEvent event) {
        if (event.captureContext() == CaptureEvent::Rescan) {
            if (event.eventType() == CaptureEvent::Started) scans.rescans_started++;
            if (event.eventType() == CaptureEvent::Finished) scans.rescans_finished++;
        } else if (event.captureContext() == CaptureEvent::Retap) {
            if (event.eventType() == CaptureEvent::Started) scans.retaps_started++;
            if (event.eventType() == CaptureEvent::Finished) scans.retaps_finished++;
        }
    });

    scans = {};
    FollowStreamDialog *dialog = openSelected(proto);
    checkStream(dialog, protocol, 0);
    checkSingleScan(QStringLiteral("selected-packet Follow"));

    auto *stream = dialog ? dialog->findChild<QSpinBox *>(QStringLiteral("streamNumberSpinBox")) : nullptr;
    check(stream && stream->maximum() >= 1, QStringLiteral("both fixture streams are available"));
    if (stream) {
        scans = {};
        QElapsedTimer timer;
        timer.start();
        stream->setValue(1);
        settleEvents();
        last_follow_elapsed = timer.elapsed();
        checkStream(dialog, protocol, 1);
        checkSingleScan(QStringLiteral("switching streams"));
    }

    scans = {};
    closeDialog(dialog);
    const QString current_filter = protocol + QStringLiteral(".stream eq 1");
    check(window->getFilter() == current_filter && QString::fromUtf8(capture->dfilter) == current_filter,
          QStringLiteral("Close preserves the current stream filter"));
    check(scans.rescans_started == 0 && scans.retaps_started == 0,
          QStringLiteral("Close does not scan the capture"));

    // A forced filter must still collect data when the text is unchanged.
    scans = {};
    dialog = openIndex(proto, 1U);
    checkStream(dialog, protocol, 1);
    checkSingleScan(QStringLiteral("reopening the same filtered stream"));

    // Another independent retap while the dialog remains open must not append
    // to its completed stream: the listener must have been removed.
    window->captureFile()->retapPackets();
    settleEvents();
    checkStream(dialog, protocol, 1);
    closeDialog(dialog);

    window->filterPackets(previous_filter);
    settleEvents();
    scans = {};
    dialog = openIndex(proto, 1U);
    checkStream(dialog, protocol, 1);
    checkSingleScan(QStringLiteral("following an explicit conversation index"));
    check(dialog && QMetaObject::invokeMethod(dialog, "backButton", Qt::DirectConnection),
          QStringLiteral("Back action runs"));
    settleEvents();
    check(window->getFilter() == previous_filter &&
          QString::fromUtf8(capture->dfilter) == previous_filter &&
          capture->displayed_count == previous_count,
          QStringLiteral("Back restores the original filter and packet list"));
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);

    window->filterPackets(QString());
    settleEvents();
    check(window->getFilter().isEmpty() && QString::fromUtf8(capture->dfilter).isEmpty() &&
          capture->displayed_count == capture->count,
          QStringLiteral("clearing the initial filter displays every packet"));
    scans = {};
    dialog = openIndex(proto, 1U);
    checkStream(dialog, protocol, 1);
    checkSingleScan(QStringLiteral("following with an empty initial filter"));
    check(dialog && QMetaObject::invokeMethod(dialog, "backButton", Qt::DirectConnection),
          QStringLiteral("Back action runs with an empty previous filter"));
    settleEvents();
    check(window->getFilter().isEmpty() && QString::fromUtf8(capture->dfilter).isEmpty() &&
          capture->displayed_count == capture->count,
          QStringLiteral("Back restores the empty filter and all packets"));
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    window->filterPackets(previous_filter);
    settleEvents();

    runLifecycleChecks(proto, protocol);

    fprintf(stderr, "FOLLOW STREAM RESULT (%s): %d failure(s)\n", qPrintable(protocol), failures);
    QCoreApplication::exit(failures ? 1 : 0);
}

void waitForCapture()
{
    for (QWidget *widget : QApplication::topLevelWidgets()) {
        window = qobject_cast<WiresharkMainWindow *>(widget);
        if (window) break;
    }
    capture = window ? window->captureFile()->capFile() : nullptr;
    if (capture && capture->count && capture->edt && !capture->read_lock) {
        settleEvents();
        runChecks();
    } else if (startup_timer.elapsed() > 30000) {
        check(false, QStringLiteral("capture ready within 30 seconds"));
        QCoreApplication::exit(1);
    } else {
        QTimer::singleShot(50, waitForCapture);
    }
}

void scheduleChecks()
{
    startup_timer.start();
    QTimer::singleShot(0, waitForCapture);
}

} // namespace

Q_COREAPP_STARTUP_FUNCTION(scheduleChecks)

int main(int argc, char **argv)
{
    return wireshark_application_main(argc, argv);
}
