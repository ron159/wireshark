/** @file
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include <QByteArray>
#include <QString>
#include <QVector>
#include <functional>

namespace PacketComparison {
struct Field {
    QString key, label, value, source;
    int type = 0;
    int start = -1, length = 0;
    bool generated = false, metadata = false, container = false;
    QVector<int> children;
};
struct Packet {
    struct Source { QString name; QByteArray bytes; unsigned reportedLength; };
    unsigned number = 0, reportedLength = 0;
    QByteArray bytes;
    QVector<Field> fields;
    QVector<int> roots;
    QVector<Source> sources;
};
enum class State { Equal, Changed, LeftOnly, RightOnly, TypeChanged };
struct Row {
    int left = -1, right = -1;
    State state = State::Equal;
    State valueState = State::Equal;
    bool uncertain = false;
    QVector<Row> children;
};
struct ByteRange { int start, length; State state; };
using ValueEqual = std::function<bool(int left, int right)>;

// The caller supplies typed equality while both dissection contexts are alive.
// Results contain indices and owned data only; no epan pointers escape.
QVector<Row> compare(const Packet &left, const Packet &right, const ValueEqual &equal);
QVector<ByteRange> compareBytes(const QByteArray &left, const QByteArray &right);
}
