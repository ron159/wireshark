/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef ANALYSIS_SESSION_H
#define ANALYSIS_SESSION_H

#include <QByteArray>
#include <QList>
#include <QString>
#include <QStringList>
#include <atomic>
#include <memory>

namespace AnalysisSession {

struct Bookmark {
    unsigned frame = 0;
    QString title;
    QString note;
};

struct Column {
    QString key;
    unsigned width = 100;
    bool visible = true;
};

struct State {
    QString capturePath;
    QByteArray captureHash;
    QString readFilter;
    QByteArray frameSequence;
    QString displayFilter;
    unsigned packetCount = 0;
    unsigned selectedFrame = 0;
    QList<unsigned> marked, ignored, timeReferences;
    QList<Bookmark> bookmarks;
    QList<Column> columns;
    int sortColumn = -1;
    bool sortDescending = false;
};

struct Fingerprint {
    QByteArray hash;
    qint64 size = 0;
    qint64 modified = 0;
    QByteArray revision;
    QString error;
};

// Run on a worker: never reads capture_file or any GUI object.
Fingerprint fingerprint(const QString &path, const std::shared_ptr<std::atomic_bool> &cancel);
QByteArray fileRevision(const QString &path);
bool read(const QString &path, State &state, QString &error);
bool write(const QString &path, const State &state, QString &error);
QString bookmarkFileName(const State &state);

// Reload under a lock before merging, so other windows' unrelated edits survive.
bool updateBookmarks(const QString &path, const State &identity, const QList<Bookmark> &updates,
                     const QList<unsigned> &removed, QList<Bookmark> &result, QString &error,
                     bool importIfMissing = false);

} // namespace AnalysisSession
#endif
