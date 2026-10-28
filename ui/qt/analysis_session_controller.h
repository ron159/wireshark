/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ANALYSIS_SESSION_CONTROLLER_H
#define ANALYSIS_SESSION_CONTROLLER_H

#include "config.h"
#include "utils/analysis_session.h"
#include "capture_event.h"
#include <QObject>
#include <QPointer>
#include <functional>

class WiresharkMainWindow;
class PacketList;
class QAction;
class QDockWidget;
class QLabel;
class QLineEdit;
class QPushButton;
class QTreeWidget;

class AnalysisSessionController : public QObject
{
    Q_OBJECT
public:
    AnalysisSessionController(WiresharkMainWindow *window, PacketList *packets);
    ~AnalysisSessionController() override;
    bool isReady() const;
    const QList<AnalysisSession::Bookmark> &bookmarks() const { return state_.bookmarks; }
    QString lastError() const { return error_; }
    bool saveSession(const QString &path);
    bool openSession(const QString &path, const QString &relocatedCapture = QString());
    bool setBookmark(unsigned frame, const QString &title, const QString &note);
    bool removeBookmark(unsigned frame);
    void goToBookmark(unsigned frame);

signals:
    void readyChanged();
    void restoreFinished(bool success);

private:
    void captureEvent(CaptureEvent event);
    void identifyCapture(bool migrateBookmarks = false);
    void hashFile(const QString &path, std::function<void(const AnalysisSession::Fingerprint &)> finished);
    void cancelHash();
    bool checkRevision();
    bool fail(const QString &message);
    void updateActions();
    void refreshBookmarks();
    void editBookmark(unsigned frame);
    void navigateBookmark(bool forward);
    QString bookmarkPath() const;
    QStringList columnKeys() const;
    QByteArray frameSequence() const;
    void applySession(const AnalysisSession::State &saved, const QString &capturePath,
                      const AnalysisSession::Fingerprint &identity);
    void filterFinished(bool success);

    WiresharkMainWindow *window_;
    PacketList *packets_;
    AnalysisSession::State state_;
    AnalysisSession::Fingerprint identity_;
    AnalysisSession::State restoring_state_;
    QString error_;
    std::shared_ptr<std::atomic_bool> cancel_;
    unsigned generation_ = 0;
    bool hashing_ = false;
    bool restore_check_ = false;
    bool restoring_ = false;
    bool scanning_ = false;
    unsigned pending_jump_ = 0;
    QAction *save_action_, *open_action_, *add_action_, *previous_action_, *next_action_;
    QDockWidget *dock_;
    QLabel *status_;
    QLineEdit *search_;
    QTreeWidget *tree_;
    QPushButton *edit_, *remove_, *jump_;
};
#endif
