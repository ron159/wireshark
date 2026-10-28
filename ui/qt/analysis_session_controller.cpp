/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "config.h"
#include "analysis_session_controller.h"
#include "wireshark_main_window.h"
#include "packet_list.h"
#include "main_status_bar.h"
#include "file.h"
#include <app/application_flavor.h>
#include <epan/column.h>
#include <epan/dfilter/dfilter.h>
#include <epan/frame_data_sequence.h>
#include <wsutil/filesystem.h>
#include <ui/recent.h>
#include <QAction>
#include <QCryptographicHash>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QDockWidget>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QFutureWatcher>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSet>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QtConcurrent>

using AnalysisSession::Bookmark;
using AnalysisSession::Fingerprint;
using AnalysisSession::State;

namespace {
// Cocoa's native push-button bezel can ignore the application's dark palette.
// Scope palette-based painting to these new controls, including their editor.
const char bookmark_button_style[] =
    "QPushButton { background: palette(button); color: palette(button-text);"
    " border: 1px solid palette(mid); border-radius: 3px; padding: 4px 8px; }"
    "QPushButton:hover:enabled { background: palette(midlight); }"
    "QPushButton:pressed { background: palette(dark); }"
    "QPushButton:focus { border-color: palette(highlight); }";
}

AnalysisSessionController::AnalysisSessionController(WiresharkMainWindow *window, PacketList *packets)
    : QObject(window), window_(window), packets_(packets)
{
    setObjectName("analysisSessionController");
    auto action = [this](const char *name, const QString &text) {
        auto *result = new QAction(text, window_);
        result->setObjectName(QLatin1String(name));
        return result;
    };
    save_action_ = action("actionSaveAnalysisSession", tr("Save Analysis Session…"));
    open_action_ = action("actionOpenAnalysisSession", tr("Open Analysis Session…"));
    add_action_ = action("actionAddPacketBookmark", tr("Add or Edit Packet Bookmark…"));
    previous_action_ = action("actionPreviousPacketBookmark", tr("Previous Bookmark"));
    next_action_ = action("actionNextPacketBookmark", tr("Next Bookmark"));
    auto *file_menu = window_->findChild<QMenu *>("menuFile");
    auto *anchor = window_->findChild<QAction *>("actionFileSave");
    file_menu->insertAction(anchor, open_action_);
    file_menu->insertAction(anchor, save_action_);
    file_menu->insertSeparator(anchor);
    auto *go_menu = window_->findChild<QMenu *>("menuGo");
    go_menu->addSeparator();
    go_menu->addAction(add_action_);
    go_menu->addAction(previous_action_);
    go_menu->addAction(next_action_);

    dock_ = new QDockWidget(tr("Packet Bookmarks"), window_);
    dock_->setObjectName("packetBookmarksDock");
    auto *body = new QWidget(dock_);
    body->setStyleSheet(QLatin1String(bookmark_button_style));
    auto *layout = new QVBoxLayout(body);
    status_ = new QLabel(body);
    status_->setObjectName("bookmarkStatus");
    status_->setWordWrap(true);
    status_->setTextFormat(Qt::PlainText);
    search_ = new QLineEdit(body);
    search_->setObjectName("bookmarkSearch");
    search_->setPlaceholderText(tr("Search packet number, title or note"));
    search_->setClearButtonEnabled(true);
    tree_ = new QTreeWidget(body);
    tree_->setObjectName("packetBookmarks");
    tree_->setHeaderLabels({tr("Packet"), tr("Title"), tr("Note")});
    tree_->setRootIsDecorated(false);
    tree_->setSelectionMode(QAbstractItemView::SingleSelection);
    tree_->header()->setStretchLastSection(true);
    tree_->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    auto *buttons = new QHBoxLayout;
    auto *add = new QPushButton(tr("Add"), body);
    add->setObjectName("addBookmark");
    edit_ = new QPushButton(tr("Edit"), body);
    edit_->setObjectName("editBookmark");
    remove_ = new QPushButton(tr("Remove"), body);
    remove_->setObjectName("removeBookmark");
    jump_ = new QPushButton(tr("Go to Packet"), body);
    jump_->setObjectName("goToBookmark");
    for (auto *button : {add, edit_, remove_, jump_}) buttons->addWidget(button);
    layout->addWidget(status_);
    layout->addWidget(search_);
    layout->addWidget(tree_);
    layout->addLayout(buttons);
    dock_->setWidget(body);
    window_->addDockWidget(Qt::RightDockWidgetArea, dock_);
    dock_->hide();
    auto *show = dock_->toggleViewAction();
    show->setObjectName("actionPacketBookmarks");
    window_->findChild<QMenu *>("menuView")->addAction(show);
    go_menu->addAction(show);
    connect(search_, &QLineEdit::textChanged, this, &AnalysisSessionController::refreshBookmarks);
    connect(tree_, &QTreeWidget::itemSelectionChanged, this, &AnalysisSessionController::updateActions);
    auto selected = [this]() { return tree_->currentItem() ? tree_->currentItem()->data(0, Qt::UserRole).toUInt() : 0U; };
    connect(tree_, &QTreeWidget::itemActivated, this, [this, selected]() { goToBookmark(selected()); });
    connect(jump_, &QPushButton::clicked, this, [this, selected]() { goToBookmark(selected()); });
    connect(edit_, &QPushButton::clicked, this, [this, selected]() { editBookmark(selected()); });
    connect(remove_, &QPushButton::clicked, this, [this, selected]() { removeBookmark(selected()); });
    connect(add, &QPushButton::clicked, add_action_, &QAction::trigger);
    connect(add_action_, &QAction::changed, add, [this, add]() { add->setEnabled(add_action_->isEnabled()); });
    connect(add_action_, &QAction::triggered, this, [this]() {
        const auto frames = window_->selectedFrames();
        if (frames.size() == 1) editBookmark(frames.first()->num);
    });
    connect(previous_action_, &QAction::triggered, this, [this]() { navigateBookmark(false); });
    connect(next_action_, &QAction::triggered, this, [this]() { navigateBookmark(true); });
    connect(save_action_, &QAction::triggered, this, [this]() {
        QString path = QFileDialog::getSaveFileName(window_, tr("Save Analysis Session"),
            state_.capturePath + ".wsanalysis", tr("Wireshark Analysis (*.wsanalysis)"));
        if (path.isEmpty()) return;
        if (!path.endsWith(".wsanalysis", Qt::CaseInsensitive)) path += ".wsanalysis";
        if (!saveSession(path)) QMessageBox::warning(window_, tr("Analysis Session"), error_);
    });
    connect(open_action_, &QAction::triggered, this, [this]() {
        const QString path = QFileDialog::getOpenFileName(window_, tr("Open Analysis Session"), {},
                                                          tr("Wireshark Analysis (*.wsanalysis)"));
        if (path.isEmpty()) return;
        State saved;
        QString error;
        if (!AnalysisSession::read(path, saved, error)) { fail(error); return; }
        QString capture = QFileInfo(path).dir().absoluteFilePath(saved.capturePath);
        if (!QFileInfo::exists(capture)) {
            capture = QFileDialog::getOpenFileName(window_, tr("Locate Capture File"), QFileInfo(path).absolutePath());
            if (capture.isEmpty()) return;
        }
        openSession(path, capture);
    });
    connect(window_->captureFile(), &CaptureFile::captureEvent, this, &AnalysisSessionController::captureEvent);
    connect(window_, &MainWindow::framesSelected, this, &AnalysisSessionController::updateActions);
    connect(window_, &MainWindow::displayFilterSuccess, this, &AnalysisSessionController::filterFinished);
    updateActions();
}

AnalysisSessionController::~AnalysisSessionController() { cancelHash(); }

bool AnalysisSessionController::isReady() const
{
    auto *cf = window_->captureFile()->capFile();
    return cf && cf->state == FILE_READ_DONE && !cf->read_lock && !cf->is_tempfile
        && !hashing_ && !restoring_ && !scanning_ && !state_.captureHash.isEmpty()
        && cf->filename && QFileInfo(QString::fromUtf8(cf->filename)).absoluteFilePath() == state_.capturePath;
}

bool AnalysisSessionController::fail(const QString &message)
{
    error_ = message;
    status_->setText(message);
    dock_->show();
    return false;
}

void AnalysisSessionController::cancelHash()
{
    if (cancel_) cancel_->store(true);
    ++generation_;
    hashing_ = false;
    if (restore_check_) {
        restore_check_ = false;
        emit restoreFinished(false);
    }
}

void AnalysisSessionController::hashFile(const QString &path, std::function<void(const Fingerprint &)> finished)
{
    cancelHash();
    hashing_ = true;
    cancel_ = std::make_shared<std::atomic_bool>(false);
    const auto cancel = cancel_;
    const unsigned generation = generation_;
    auto *watcher = new QFutureWatcher<Fingerprint>(this);
    connect(watcher, &QFutureWatcher<Fingerprint>::finished, this, [this, watcher, generation, finished]() {
        const auto result = watcher->result();
        watcher->deleteLater();
        if (generation != generation_) return;
        hashing_ = false;
        finished(result);
        updateActions();
        emit readyChanged();
    });
    watcher->setFuture(QtConcurrent::run([path, cancel]() { return AnalysisSession::fingerprint(path, cancel); }));
    status_->setText(tr("Checking capture identity… You can continue reading packets."));
    updateActions();
}

void AnalysisSessionController::captureEvent(CaptureEvent event)
{
    auto context = event.captureContext();
    auto type = event.eventType();
    if (context == CaptureEvent::File && type == CaptureEvent::Closing) {
        if (restoring_) return;
        cancelHash();
        state_ = State();
        identity_ = Fingerprint();
        pending_jump_ = 0;
        error_.clear();
        refreshBookmarks();
    }
    if (type == CaptureEvent::Started) scanning_ = true;
    if (type == CaptureEvent::Finished || type == CaptureEvent::Closed || type == CaptureEvent::Failed
        || type == CaptureEvent::Stopped) scanning_ = false;
    bool capture_finished = false;
#ifdef HAVE_LIBPCAP
    capture_finished = context == CaptureEvent::Update || context == CaptureEvent::Fixed;
#endif
    if (!restoring_ && type == CaptureEvent::Finished &&
        (context == CaptureEvent::File || context == CaptureEvent::Reload || context == CaptureEvent::Save || capture_finished)) {
        // File callbacks can fire before the core releases read_lock / updates filename.
        QTimer::singleShot(0, this, [this, context]() { identifyCapture(context == CaptureEvent::Save); });
    }
    updateActions();
}

void AnalysisSessionController::identifyCapture(bool migrateBookmarks)
{
    auto *cf = window_->captureFile()->capFile();
    if (!cf || cf->state != FILE_READ_DONE || cf->is_tempfile || !cf->filename || cf->read_lock) return;
    auto previous = migrateBookmarks ? state_.bookmarks : QList<Bookmark>();
    if (migrateBookmarks && !state_.captureHash.isEmpty() && QFileInfo::exists(bookmarkPath())) {
        State latest;
        QString error;
        if (!AnalysisSession::read(bookmarkPath(), latest, error)) { fail(error); return; }
        previous = latest.bookmarks;
    }
    const QString path = QFileInfo(QString::fromUtf8(cf->filename)).absoluteFilePath();
    state_ = State();
    state_.capturePath = path;
    state_.packetCount = cf->count;
    if (cf->rfcode) state_.readFilter = QString::fromUtf8(dfilter_text(cf->rfcode));
    state_.frameSequence = frameSequence();
    refreshBookmarks();
    hashFile(path, [this, previous, path](const Fingerprint &identity) {
        if (!identity.error.isEmpty() || identity.hash.isEmpty()) {
            fail(identity.error.isEmpty() ? tr("Capture identity check was cancelled.") : identity.error); return;
        }
        if (AnalysisSession::fileRevision(path) != identity.revision) {
            fail(tr("The capture file changed. Reload it before saving analysis.")); return;
        }
        identity_ = identity;
        state_.captureHash = identity.hash;
        State stored;
        QString error;
        if (!previous.isEmpty()) {
            if (!AnalysisSession::updateBookmarks(bookmarkPath(), state_, previous, {}, state_.bookmarks, error, true)) fail(error);
        } else if (QFileInfo::exists(bookmarkPath())) {
            if (!AnalysisSession::read(bookmarkPath(), stored, error)) fail(error);
            else if (stored.captureHash != state_.captureHash || stored.readFilter != state_.readFilter
                     || stored.frameSequence != state_.frameSequence || stored.packetCount != state_.packetCount)
                fail(tr("Saved bookmarks do not match this capture."));
            else state_.bookmarks = stored.bookmarks;
        }
        refreshBookmarks();
    });
}

QString AnalysisSessionController::bookmarkPath() const
{
    char *raw = get_persconffile_path("packet_bookmarks", false, application_configuration_environment_prefix());
    const QString directory = QString::fromUtf8(raw);
    g_free(raw);
    return QDir(directory).filePath(AnalysisSession::bookmarkFileName(state_));
}

bool AnalysisSessionController::checkRevision()
{
    if (!isReady()) return fail(tr("Stop and save the capture, then wait for its identity check to finish."));
    if (AnalysisSession::fileRevision(state_.capturePath) != identity_.revision)
        return fail(tr("The capture file changed. Reload it before saving analysis."));
    error_.clear();
    return true;
}

void AnalysisSessionController::updateActions()
{
    const bool ready = isReady();
    save_action_->setEnabled(ready);
    auto *open_capture = window_->findChild<QAction *>("actionFileOpen");
    open_action_->setEnabled(open_capture && open_capture->isEnabled() && !scanning_ && !restoring_);
    add_action_->setEnabled(ready && window_->hasUniqueSelection());
    next_action_->setEnabled(ready && !state_.bookmarks.isEmpty());
    previous_action_->setEnabled(ready && !state_.bookmarks.isEmpty());
    const bool selected = ready && tree_->currentItem() && !tree_->currentItem()->isHidden();
    for (auto *button : {edit_, remove_, jump_}) button->setEnabled(selected);
    if (!error_.isEmpty()) status_->setText(error_);
    else if (hashing_) status_->setText(tr("Checking capture identity… You can continue reading packets."));
    else if (restoring_) status_->setText(tr("Restoring analysis session…"));
    else if (ready) status_->setText(tr("%1 bookmarks · Saved automatically").arg(state_.bookmarks.size()));
    else status_->setText(tr("Open a saved capture to use persistent bookmarks. Stop and save live captures first."));
}

void AnalysisSessionController::refreshBookmarks()
{
    const unsigned selected = tree_->currentItem() ? tree_->currentItem()->data(0, Qt::UserRole).toUInt() : 0;
    tree_->clear();
    const QString query = search_->text().trimmed();
    for (const auto &bookmark : state_.bookmarks) {
        auto *item = new QTreeWidgetItem(tree_, {QString::number(bookmark.frame), bookmark.title, bookmark.note.simplified().left(200)});
        item->setData(0, Qt::UserRole, bookmark.frame);
        item->setToolTip(2, bookmark.note.toHtmlEscaped());
        item->setHidden(!query.isEmpty() && !QString::number(bookmark.frame).contains(query)
                        && !bookmark.title.contains(query, Qt::CaseInsensitive) && !bookmark.note.contains(query, Qt::CaseInsensitive));
        if (bookmark.frame == selected) tree_->setCurrentItem(item);
    }
    updateActions();
}

bool AnalysisSessionController::setBookmark(unsigned frame, const QString &title, const QString &note)
{
    if (!checkRevision()) return false;
    QString error;
    if (!AnalysisSession::updateBookmarks(bookmarkPath(), state_, {{frame, title, note}}, {}, state_.bookmarks, error)) return fail(error);
    refreshBookmarks();
    return true;
}

bool AnalysisSessionController::removeBookmark(unsigned frame)
{
    if (!checkRevision()) return false;
    QString error;
    if (!AnalysisSession::updateBookmarks(bookmarkPath(), state_, {}, {frame}, state_.bookmarks, error)) return fail(error);
    refreshBookmarks();
    return true;
}

void AnalysisSessionController::editBookmark(unsigned frame)
{
    if (!checkRevision() || !frame || frame > state_.packetCount) return;
    QDialog dialog(window_);
    dialog.setStyleSheet(QLatin1String(bookmark_button_style));
    dialog.setObjectName("packetBookmarkEditor");
    dialog.setWindowTitle(tr("Packet Bookmark — %1").arg(frame));
    auto *layout = new QFormLayout(&dialog);
    auto *title = new QLineEdit(tr("Packet %1").arg(frame), &dialog);
    title->setObjectName("bookmarkTitle");
    title->setMaxLength(512);
    auto *note = new QPlainTextEdit(&dialog);
    note->setObjectName("bookmarkNote");
    for (const auto &bookmark : state_.bookmarks) if (bookmark.frame == frame) {
        title->setText(bookmark.title); note->setPlainText(bookmark.note); break;
    }
    layout->addRow(tr("Title"), title);
    layout->addRow(tr("Note"), note);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, &dialog);
    layout->addRow(buttons);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    const auto generation = generation_;
    connect(buttons, &QDialogButtonBox::accepted, &dialog, [&, generation]() {
        if (generation != generation_) { dialog.reject(); return; }
        if (setBookmark(frame, title->text(), note->toPlainText())) dialog.accept();
        else QMessageBox::warning(&dialog, tr("Packet Bookmark"), error_);
    });
    dialog.resize(480, 260);
    if (dialog.exec() == QDialog::Accepted) { dock_->show(); refreshBookmarks(); }
}

void AnalysisSessionController::navigateBookmark(bool forward)
{
    if (!isReady() || state_.bookmarks.isEmpty()) return;
    auto *cf = window_->captureFile()->capFile();
    const unsigned current = cf->current_frame ? cf->current_frame->num : 0;
    unsigned target = forward ? state_.bookmarks.first().frame : state_.bookmarks.last().frame;
    for (const auto &bookmark : state_.bookmarks) {
        if (forward && bookmark.frame > current) { target = bookmark.frame; break; }
        if (!forward && bookmark.frame < current) target = bookmark.frame;
    }
    goToBookmark(target);
}

void AnalysisSessionController::goToBookmark(unsigned frame)
{
    if (!checkRevision() || !frame || frame > state_.packetCount) return;
    auto *cf = window_->captureFile()->capFile();
    const auto *packet = frame_data_sequence_find(cf->provider.frames, frame);
    if (!packet) return;
    if (packet->passed_dfilter || packet->ref_time) { window_->gotoFrame(frame); return; }
    pending_jump_ = frame;
    const QString filter = window_->captureFile()->displayFilter();
    window_->filterPackets(filter.isEmpty() ? QString() : QStringLiteral("(%1) || frame.number == %2").arg(filter).arg(frame));
}

QStringList AnalysisSessionController::columnKeys() const
{
    QStringList keys;
    for (int col = 0; col < packets_->header()->count(); ++col) {
        QByteArray signature = QByteArray(get_column_title(col)) + '\0' + QByteArray::number(get_column_format(col)) + '\0';
        signature += QByteArray(get_column_custom_fields(col)) + '\0' + QByteArray::number(get_column_custom_occurrence(col)) + '\0';
        signature += QByteArray::number(get_column_custom_dynamic(col));
        keys.append(QString::fromLatin1(QCryptographicHash::hash(signature, QCryptographicHash::Sha256).toHex()));
    }
    return keys;
}

QByteArray AnalysisSessionController::frameSequence() const
{
    auto *cf = window_->captureFile()->capFile();
    if (!cf || !cf->rfcode) return {};
    QCryptographicHash hash(QCryptographicHash::Sha256);
    // A read filter can accept different frames under another dissection profile,
    // even with the same expression and packet count. Bind to the actual offsets.
    for (unsigned frame = 1; frame <= cf->count; ++frame) {
        auto *packet = frame_data_sequence_find(cf->provider.frames, frame);
        hash.addData(QByteArray::number(packet->file_off) + ':' + QByteArray::number(packet->cap_len) + ';');
    }
    return hash.result().toHex();
}

bool AnalysisSessionController::saveSession(const QString &path)
{
    if (!checkRevision()) return false;
    if (QFileInfo(path).absoluteFilePath() == state_.capturePath
        || (!QFileInfo(path).canonicalFilePath().isEmpty()
            && QFileInfo(path).canonicalFilePath() == QFileInfo(state_.capturePath).canonicalFilePath()))
        return fail(tr("Choose a separate analysis file; the capture file cannot be overwritten."));
    auto *cf = window_->captureFile()->capFile();
    if (cf->unsaved_changes) return fail(tr("Save changes to the capture file before saving the analysis session."));
    State saved = state_;
    // Re-read to include bookmarks added from other windows after our last edit.
    if (QFileInfo::exists(bookmarkPath())) {
        State latest;
        QString error;
        if (!AnalysisSession::read(bookmarkPath(), latest, error)) return fail(error);
        if (latest.captureHash != state_.captureHash || latest.readFilter != state_.readFilter
            || latest.frameSequence != state_.frameSequence || latest.packetCount != state_.packetCount)
            return fail(tr("Saved bookmarks do not match this capture."));
        saved.bookmarks = latest.bookmarks;
    }
    saved.capturePath = QFileInfo(path).dir().relativeFilePath(state_.capturePath);
    saved.displayFilter = window_->captureFile()->displayFilter();
    saved.selectedFrame = cf->current_frame ? cf->current_frame->num : 0;
    const auto keys = columnKeys();
    saved.columns.clear();
    for (int col = 0; col < keys.size(); ++col) {
        const int width = packets_->isColumnHidden(col) ? recent_get_column_width(col) : packets_->header()->sectionSize(col);
        saved.columns.append({keys[col], static_cast<unsigned>(qBound(1, width, 10000)), !packets_->isColumnHidden(col)});
    }
    saved.sortColumn = packets_->header()->sortIndicatorSection();
    saved.sortDescending = packets_->header()->sortIndicatorOrder() == Qt::DescendingOrder;
    for (unsigned frame = 1; frame <= cf->count; ++frame) {
        const auto *packet = frame_data_sequence_find(cf->provider.frames, frame);
        if (packet->marked) saved.marked.append(frame);
        if (packet->ignored) saved.ignored.append(frame);
        if (packet->ref_time) saved.timeReferences.append(frame);
    }
    QString error;
    if (!AnalysisSession::write(path, saved, error)) return fail(error);
    state_.bookmarks = saved.bookmarks;
    refreshBookmarks();
    window_->statusBar()->showMessage(tr("Analysis session saved: %1").arg(QDir::toNativeSeparators(path)), 6000);
    return true;
}

bool AnalysisSessionController::openSession(const QString &path, const QString &relocatedCapture)
{
    auto *cf = window_->captureFile()->capFile();
    if (restoring_ || (cf && (cf->read_lock || cf->state == FILE_READ_IN_PROGRESS)))
        return fail(tr("Finish the current capture or file operation before opening an analysis session."));
    State saved;
    QString error;
    if (!AnalysisSession::read(path, saved, error)) return fail(error);
    for (const auto &filter : {saved.readFilter, saved.displayFilter}) {
        dfilter_t *compiled = nullptr;
        df_error_t *filter_error = nullptr;
        if (!dfilter_compile(qUtf8Printable(filter), &compiled, &filter_error)) {
            const QString message = QString::fromUtf8(filter_error->msg);
            df_error_free(&filter_error);
            return fail(tr("Cannot restore analysis filter: %1").arg(message));
        }
        dfilter_free(compiled);
    }
    QString capture = relocatedCapture.isEmpty() ? QFileInfo(path).dir().absoluteFilePath(saved.capturePath) : relocatedCapture;
    capture = QFileInfo(capture).absoluteFilePath();
    if (!QFileInfo(capture).isFile()) return fail(tr("Capture file is missing. Locate the original capture to restore this session."));
    error_.clear();
    hashFile(capture, [this, saved, capture](const Fingerprint &identity) {
        restore_check_ = false;
        if (!identity.error.isEmpty() || identity.hash.isEmpty()) {
            fail(identity.error.isEmpty() ? tr("Capture identity check was cancelled.") : identity.error);
            emit restoreFinished(false);
            return;
        }
        if (identity.hash != saved.captureHash || AnalysisSession::fileRevision(capture) != identity.revision) {
            fail(tr("Capture contents do not match this analysis session. The current analysis was left unchanged."));
            emit restoreFinished(false);
            return;
        }
        applySession(saved, capture, identity);
    });
    restore_check_ = true;
    return true;
}

void AnalysisSessionController::applySession(const State &saved, const QString &path, const Fingerprint &identity)
{
    restoring_ = true;
    updateActions();
    if (!window_->openCaptureFile(path, saved.readFilter)) {
        restoring_ = false; updateActions(); emit restoreFinished(false); return;
    }
    auto *cf = window_->captureFile()->capFile();
    if (!cf || cf->count != saved.packetCount || frameSequence() != saved.frameSequence
        || AnalysisSession::fileRevision(path) != identity.revision) {
        restoring_ = false;
        state_ = State();
        fail(tr("The opened capture does not match the saved packet sequence. Analysis state was not applied."));
        updateActions(); emit restoreFinished(false); return;
    }
    state_ = State();
    state_.capturePath = path;
    state_.captureHash = identity.hash;
    state_.readFilter = saved.readFilter;
    state_.frameSequence = saved.frameSequence;
    state_.packetCount = cf->count;
    identity_ = identity;
    QString error;
    // A snapshot is a portable fallback. Existing local bookmarks (including
    // later edits and deletions) remain authoritative when reopening old work.
    if (!AnalysisSession::updateBookmarks(bookmarkPath(), state_, saved.bookmarks, {}, state_.bookmarks, error, true)) {
        restoring_ = false; fail(error); updateActions(); emit restoreFinished(false); return;
    }
    QSet<unsigned> marked(saved.marked.begin(), saved.marked.end());
    QSet<unsigned> ignored(saved.ignored.begin(), saved.ignored.end());
    QSet<unsigned> references(saved.timeReferences.begin(), saved.timeReferences.end());
    cf->ref_time_count = 0;
    for (unsigned frame = 1; frame <= cf->count; ++frame) {
        auto *packet = frame_data_sequence_find(cf->provider.frames, frame);
        if (marked.contains(frame)) cf_mark_frame(cf, packet); else cf_unmark_frame(cf, packet);
        if (ignored.contains(frame)) cf_ignore_frame(cf, packet); else cf_unignore_frame(cf, packet);
        packet->ref_time = references.contains(frame);
        cf->ref_time_count += packet->ref_time;
    }
    cf_reftime_packets(cf);
    restoring_state_ = saved;
    // Ignored frames affect dissection of later packets; perform a real redissection.
    if (!saved.ignored.isEmpty()) cf_redissect_packets(cf);
    window_->filterPackets(saved.displayFilter);
}

void AnalysisSessionController::filterFinished(bool success)
{
    if (restoring_) {
        if (success) {
            auto current = columnKeys();
            QStringList expected;
            for (const auto &column : restoring_state_.columns) expected.append(column.key);
            auto sorted_current = current, sorted_expected = expected;
            sorted_current.sort(); sorted_expected.sort();
            if (sorted_current == sorted_expected) {
                for (int target = 0; target < expected.size(); ++target) {
                    const int source = static_cast<int>(current.indexOf(expected[target], target));
                    if (source != target) {
                        packets_->header()->moveSection(source, target);
                        current.move(source, target);
                    }
                }
                for (int col = 0; col < packets_->header()->count(); ++col) {
                    const auto &column = restoring_state_.columns[col];
                    set_column_visible(col, column.visible);
                    packets_->header()->resizeSection(col, static_cast<int>(column.width));
                    recent_set_column_width(col, static_cast<int>(column.width));
                }
                packets_->setColumnVisibility();
                packets_->sortByColumn(restoring_state_.sortColumn,
                    restoring_state_.sortDescending ? Qt::DescendingOrder : Qt::AscendingOrder);
            } else window_->statusBar()->showMessage(tr("Analysis restored; column layout was skipped because column definitions differ."), 8000);
            auto *cf = window_->captureFile()->capFile();
            auto *selected = cf && restoring_state_.selectedFrame
                ? frame_data_sequence_find(cf->provider.frames, restoring_state_.selectedFrame) : nullptr;
            if (selected && (selected->passed_dfilter || selected->ref_time)) window_->gotoFrame(selected->num);
            else if (selected) window_->statusBar()->showMessage(tr("Analysis restored; the saved selection is hidden by its display filter."), 8000);
        } else fail(tr("The analysis display filter could not be applied."));
        restoring_ = false;
        refreshBookmarks();
        dock_->show();
        emit restoreFinished(success);
    }
    if (pending_jump_) {
        const unsigned frame = pending_jump_;
        pending_jump_ = 0;
        if (success && isReady()) {
            window_->gotoFrame(frame);
            window_->statusBar()->showMessage(tr("The bookmarked packet was added to the current display filter."), 6000);
        }
    }
    updateActions();
}
