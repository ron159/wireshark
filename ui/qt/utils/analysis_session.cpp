/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "analysis_session.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLockFile>
#include <QMap>
#include <QObject>
#include <QSaveFile>
#include <QSet>
#include <cmath>
#include <limits>
#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <io.h>
#else
#include <sys/stat.h>
#endif

namespace AnalysisSession {
namespace {
constexpr qint64 maxFileSize = 16 * 1024 * 1024;
constexpr int maxBookmarks = 10000;
constexpr int maxFrameList = 100000;

QByteArray revision(QFile &file)
{
#ifdef Q_OS_WIN
    BY_HANDLE_FILE_INFORMATION info;
    auto handle = reinterpret_cast<HANDLE>(_get_osfhandle(file.handle()));
    if (!GetFileInformationByHandle(handle, &info)) return {};
    return QByteArray::number(info.dwVolumeSerialNumber) + ':' + QByteArray::number(info.nFileIndexHigh)
        + ':' + QByteArray::number(info.nFileIndexLow) + ':' + QByteArray::number(info.nFileSizeHigh)
        + ':' + QByteArray::number(info.nFileSizeLow) + ':' + QByteArray::number(info.ftLastWriteTime.dwHighDateTime)
        + ':' + QByteArray::number(info.ftLastWriteTime.dwLowDateTime);
#else
    struct stat info;
    if (fstat(file.handle(), &info) != 0) return {};
#ifdef Q_OS_MACOS
    const auto modified = info.st_mtimespec, changed = info.st_ctimespec;
#else
    const auto modified = info.st_mtim, changed = info.st_ctim;
#endif
    return QByteArray::number(static_cast<qulonglong>(info.st_dev)) + ':'
        + QByteArray::number(static_cast<qulonglong>(info.st_ino)) + ':'
        + QByteArray::number(static_cast<qlonglong>(info.st_size)) + ':'
        + QByteArray::number(static_cast<qlonglong>(modified.tv_sec)) + ':' + QByteArray::number(modified.tv_nsec)
        + ':' + QByteArray::number(static_cast<qlonglong>(changed.tv_sec)) + ':' + QByteArray::number(changed.tv_nsec);
#endif
}

bool number(const QJsonValue &value, unsigned &out)
{
    double n = value.toDouble(-1);
    if (!value.isDouble() || n < 0 || n > std::numeric_limits<int>::max() || std::floor(n) != n)
        return false;
    out = static_cast<unsigned>(n);
    return true;
}

bool frames(const QJsonValue &value, unsigned count, QList<unsigned> &out)
{
    if (!value.isArray() || value.toArray().size() > maxFrameList) return false;
    QSet<unsigned> seen;
    for (const auto &entry : value.toArray()) {
        unsigned frame;
        if (!number(entry, frame) || !frame || frame > count || seen.contains(frame)) return false;
        seen.insert(frame);
        out.append(frame);
    }
    return true;
}

QJsonArray array(const QList<unsigned> &frames)
{
    QJsonArray result;
    for (unsigned frame : frames) result.append(static_cast<qint64>(frame));
    return result;
}

bool decode(const QByteArray &bytes, State &state, QString &error)
{
    QJsonParseError parse;
    const auto document = QJsonDocument::fromJson(bytes, &parse);
    if (parse.error != QJsonParseError::NoError || !document.isObject()) {
        error = QObject::tr("Invalid analysis file: %1").arg(parse.errorString());
        return false;
    }
    const auto root = document.object();
    if (root.value("format") != "wireshark-analysis" || root.value("version") != 1) {
        error = QObject::tr("Unsupported analysis file format or version.");
        return false;
    }
    State next;
    auto string = [&](const char *key, QString &out, int limit) {
        auto value = root.value(QLatin1String(key));
        if (!value.isString() || value.toString().size() > limit || value.toString().contains(QChar(0))) return false;
        out = value.toString();
        return true;
    };
    QString hash, signature, header;
    bool valid = string("capture", next.capturePath, 32768) && !next.capturePath.isEmpty()
        && string("sha256", hash, 64) && hash.size() == 64
        && QByteArray::fromHex(hash.toLatin1()).toHex() == hash.toLatin1()
        && string("read_filter", next.readFilter, 65536)
        && string("display_filter", next.displayFilter, 65536)
        && number(root.value("packet_count"), next.packetCount)
        && number(root.value("selected_frame"), next.selectedFrame) && next.selectedFrame <= next.packetCount
        && frames(root.value("marked"), next.packetCount, next.marked)
        && frames(root.value("ignored"), next.packetCount, next.ignored)
        && frames(root.value("time_references"), next.packetCount, next.timeReferences)
        && string("column_signature", signature, 128)
        && string("header_state", header, 262144)
        && root.value("bookmarks").isArray() && root.value("bookmarks").toArray().size() <= maxBookmarks;
    QSet<unsigned> seen;
    if (valid) {
        for (const auto &value : root.value("bookmarks").toArray()) {
            const auto item = value.toObject();
            Bookmark bookmark;
            if (!value.isObject() || !number(item.value("frame"), bookmark.frame)
                || !bookmark.frame || bookmark.frame > next.packetCount || seen.contains(bookmark.frame)
                || !item.value("title").isString() || !item.value("note").isString()) {
                valid = false;
                break;
            }
            bookmark.title = item.value("title").toString();
            bookmark.note = item.value("note").toString();
            if (bookmark.title.size() > 512 || bookmark.note.size() > 16384
                || bookmark.title.contains(QChar(0)) || bookmark.note.contains(QChar(0))) {
                valid = false;
                break;
            }
            seen.insert(bookmark.frame);
            next.bookmarks.append(bookmark);
        }
    }
    if (!valid) {
        error = QObject::tr("Invalid or oversized analysis data. No state was restored.");
        return false;
    }
    next.captureHash = hash.toLatin1();
    next.columnSignature = signature.toLatin1();
    next.headerState = QByteArray::fromBase64(header.toLatin1());
    if (next.headerState.toBase64() != header.toLatin1()) {
        error = QObject::tr("Invalid column layout data.");
        return false;
    }
    state = next;
    return true;
}
}

Fingerprint fingerprint(const QString &path, const std::shared_ptr<std::atomic_bool> &cancel)
{
    Fingerprint result;
    if (cancel && cancel->load()) return result;
    QFile file(path);
    QFileInfo before(path);
    result.size = before.size();
    result.modified = before.lastModified().toMSecsSinceEpoch();
    if (!before.isFile() || !file.open(QIODevice::ReadOnly)) {
        result.error = QObject::tr("Cannot read capture file: %1").arg(path);
        return result;
    }
    result.revision = revision(file);
    QCryptographicHash hash(QCryptographicHash::Sha256);
    QByteArray buffer(1024 * 1024, Qt::Uninitialized);
    while (!file.atEnd()) {
        if (cancel && cancel->load()) return result;
        qint64 length = file.read(buffer.data(), buffer.size());
        if (length <= 0) {
            result.error = file.errorString();
            return result;
        }
        hash.addData(QByteArrayView(buffer.constData(), length));
    }
    QFileInfo after(path);
    if (result.revision.isEmpty() || revision(file) != result.revision || fileRevision(path) != result.revision
        || after.size() != result.size || after.lastModified().toMSecsSinceEpoch() != result.modified) {
        result.error = QObject::tr("The capture file changed while its identity was being checked. Reload it and try again.");
        return result;
    }
    result.hash = hash.result().toHex();
    return result;
}

QByteArray fileRevision(const QString &path)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return {};
    return revision(file);
}

bool read(const QString &path, State &state, QString &error)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) { error = file.errorString(); return false; }
    if (file.size() > maxFileSize) { error = QObject::tr("Analysis file exceeds 16 MiB."); return false; }
    const auto bytes = file.read(maxFileSize + 1);
    if (bytes.size() > maxFileSize || file.error() != QFileDevice::NoError) {
        error = QObject::tr("Could not read analysis file safely.");
        return false;
    }
    return decode(bytes, state, error);
}

bool write(const QString &path, const State &state, QString &error)
{
    QJsonArray bookmarks;
    for (const auto &b : state.bookmarks)
        bookmarks.append(QJsonObject{{"frame", static_cast<qint64>(b.frame)}, {"title", b.title}, {"note", b.note}});
    QJsonObject root{{"format", "wireshark-analysis"}, {"version", 1}, {"capture", state.capturePath},
        {"sha256", QString::fromLatin1(state.captureHash)}, {"read_filter", state.readFilter},
        {"display_filter", state.displayFilter}, {"packet_count", static_cast<qint64>(state.packetCount)},
        {"selected_frame", static_cast<qint64>(state.selectedFrame)}, {"marked", array(state.marked)},
        {"ignored", array(state.ignored)}, {"time_references", array(state.timeReferences)},
        {"bookmarks", bookmarks}, {"column_signature", QString::fromLatin1(state.columnSignature)},
        {"header_state", QString::fromLatin1(state.headerState.toBase64())}};
    const auto bytes = QJsonDocument(root).toJson();
    State validated;
    if (bytes.size() > maxFileSize || !decode(bytes, validated, error)) {
        if (error.isEmpty()) error = QObject::tr("Analysis file exceeds 16 MiB.");
        return false;
    }
    QSaveFile file(path);
    if (!file.open(QIODevice::WriteOnly)) { error = file.errorString(); return false; }
    file.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
    if (file.write(bytes) != bytes.size() || !file.commit()) { error = file.errorString(); return false; }
    return true;
}

QString bookmarkFileName(const State &state)
{
    auto key = state.captureHash + '\0' + state.readFilter.toUtf8();
    return QString::fromLatin1(QCryptographicHash::hash(key, QCryptographicHash::Sha256).toHex()) + ".json";
}

bool updateBookmarks(const QString &path, const State &identity, const QList<Bookmark> &updates,
                     const QList<unsigned> &removed, QList<Bookmark> &result, QString &error)
{
    if (!QDir().mkpath(QFileInfo(path).absolutePath())) {
        error = QObject::tr("Cannot create the bookmark storage directory."); return false;
    }
    QLockFile lock(path + ".lock");
    if (!lock.tryLock(0)) { error = QObject::tr("Bookmarks are being saved by another window. Try again."); return false; }
    State stored = identity;
    stored.bookmarks.clear();
    if (QFileInfo::exists(path) && !read(path, stored, error)) return false;
    if (stored.captureHash != identity.captureHash || stored.readFilter != identity.readFilter
        || stored.packetCount != identity.packetCount) {
        error = QObject::tr("Saved bookmarks belong to a different capture or read filter."); return false;
    }
    QMap<unsigned, Bookmark> merged;
    for (const auto &b : stored.bookmarks) merged.insert(b.frame, b);
    for (unsigned frame : removed) merged.remove(frame);
    for (const auto &b : updates) merged.insert(b.frame, b);
    stored.bookmarks = merged.values();
    if (!write(path, stored, error)) return false;
    result = stored.bookmarks;
    return true;
}
} // namespace AnalysisSession
