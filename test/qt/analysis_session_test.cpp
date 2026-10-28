/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "ui/qt/utils/analysis_session.h"
#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <cstdio>

using namespace AnalysisSession;
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    QTemporaryDir directory;
    int failures = 0;
    auto check = [&](bool condition, const char *message) {
        fprintf(stderr, "%s: %s\n", condition ? "PASS" : "FAIL", message);
        failures += !condition;
    };
    auto put = [&](const QString &path, const QByteArray &bytes) {
        QFile file(path);
        return file.open(QIODevice::WriteOnly) && file.write(bytes) == bytes.size();
    };
    const auto capture = directory.filePath("抓包.pcap");
    const auto path = directory.filePath("现场.wsanalysis");
    check(put(capture, "abc"), "capture fixture written");
    auto cancel = std::make_shared<std::atomic_bool>(false);
    auto identity = fingerprint(capture, cancel);
    check(identity.error.isEmpty() && identity.hash == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "complete capture SHA-256 is correct");
    State state;
    state.capturePath = capture;
    state.captureHash = identity.hash;
    state.packetCount = 8;
    state.selectedFrame = 3;
    state.displayFilter = "tcp.port == 443";
    state.marked = {1, 3}; state.ignored = {4}; state.timeReferences = {2};
    state.bookmarks = {{3, QString::fromUtf8("握手"), QString::fromUtf8("检查证书\n第二行")}};
    state.columns = {{QString::fromLatin1(identity.hash), 240, false}};
    state.sortColumn = 0;
    state.sortDescending = true;
    QString error;
    check(write(path, state, error), "atomic session save succeeds");
    State loaded;
    check(read(path, loaded, error) && loaded.bookmarks.size() == 1 && loaded.bookmarks[0].note == state.bookmarks[0].note
          && loaded.marked == state.marked && loaded.ignored == state.ignored && loaded.timeReferences == state.timeReferences
          && loaded.displayFilter == state.displayFilter && loaded.columns.size() == 1 && loaded.columns[0].width == 240
          && !loaded.columns[0].visible && loaded.sortColumn == 0 && loaded.sortDescending && loaded.selectedFrame == 3,
          "analysis state and Unicode multiline notes round trip");
    const auto key = bookmarkFileName(state);
    state.capturePath = directory.filePath("renamed.pcap");
    check(key == bookmarkFileName(state), "capture rename retains bookmark identity");
    state.readFilter = "tcp";
    check(key != bookmarkFileName(state), "read filters isolate frame number namespaces");
    state.readFilter.clear();
    const auto bookmarks = directory.filePath("bookmarks/" + key);
    QList<Bookmark> merged;
    check(updateBookmarks(bookmarks, state, state.bookmarks, {}, merged, error), "bookmark directory created and edit persisted");
    check(updateBookmarks(bookmarks, state, {{7, "Second window", "note"}}, {}, merged, error) && merged.size() == 2,
          "another window's unrelated bookmark survives an update");
    check(updateBookmarks(bookmarks, state, {}, {3}, merged, error) && merged.size() == 1 && merged[0].frame == 7,
          "bookmark removal preserves other entries");
    check(updateBookmarks(bookmarks, state, state.bookmarks, {}, merged, error, true) && merged.size() == 1 && merged[0].frame == 7,
          "snapshot import checks existing edits and deletions under the lock");
    auto same_filter = state;
    same_filter.frameSequence = QByteArray(64, 'a');
    check(bookmarkFileName(same_filter) != bookmarkFileName(state), "different accepted frame sequences have separate bookmark identities");
    auto corrupt = [&](const char *key, QJsonValue value) {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly)) return false;
        auto root = QJsonDocument::fromJson(file.readAll()).object(); file.close();
        root.insert(QLatin1String(key), value);
        put(directory.filePath("invalid.json"), QJsonDocument(root).toJson());
        State sentinel = loaded;
        return !read(directory.filePath("invalid.json"), sentinel, error) && sentinel.captureHash == loaded.captureHash;
    };
    check(corrupt("version", 2), "future schema rejected without mutating current state");
    check(corrupt("selected_frame", 9), "out of range frame rejected");
    check(corrupt("selected_frame", 1.5), "fractional frame rejected");
    check(corrupt("sha256", QString(64, 'z')), "invalid identity rejected");
    check(corrupt("sort_column", 1000000000), "out of range layout index rejected");
    check(corrupt("display_filter", QString(65537, 'x')), "oversized filter rejected");
    check(put(bookmarks, "broken"), "corrupt bookmark fixture written");
    check(!updateBookmarks(bookmarks, state, state.bookmarks, {}, merged, error), "corrupt bookmark file is not overwritten");
    QFile file(bookmarks);
    check(file.open(QIODevice::ReadOnly), "corrupt bookmark source remains readable");
    check(file.readAll() == "broken", "corrupt source preserved for recovery");
    check(!write(directory.filePath("missing/session.wsanalysis"), state, error), "write failure is reported");
    cancel->store(true);
    check(fingerprint(capture, cancel).hash.isEmpty(), "cancelled fingerprint produces no identity");
    check(put(capture, "abd") && fingerprint(capture, std::make_shared<std::atomic_bool>(false)).hash != identity.hash,
          "same filename and size with different contents has different identity");
    const auto replacement = directory.filePath("replacement.pcap");
    check(put(replacement, "abc") && QFile::remove(capture) && QFile::rename(replacement, capture)
          && fileRevision(capture) != identity.revision, "atomic path replacement invalidates the checked file revision");
    return failures ? 1 : 0;
}
