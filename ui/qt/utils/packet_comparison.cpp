/** @file
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "packet_comparison.h"
#include <QHash>
#include <algorithm>

namespace PacketComparison {
namespace {
class Comparison {
    const Packet &left_, &right_;
    const ValueEqual &equal_;
    QHash<quint64, bool> equivalent_cache_;
    int equality_budget_ = 131072;

    bool equivalent(int l, int r)
    {
        quint64 key = (static_cast<quint64>(l) << 32) | static_cast<unsigned>(r);
        auto found = equivalent_cache_.constFind(key);
        if (found != equivalent_cache_.cend()) return found.value();
        if (equality_budget_-- <= 0) { equality_budget_ = 0; return false; }
        const auto &a = left_.fields[l];
        const auto &b = right_.fields[r];
        bool same = a.key == b.key && a.type == b.type;
        if (same && a.container && b.container) {
            same = a.children.size() == b.children.size();
            for (int i = 0; same && i < a.children.size(); ++i)
                same = equivalent(a.children[i], b.children[i]);
        } else if (same) same = equal_(l, r);
        equivalent_cache_.insert(key, same);
        return same;
    }

    int cost(int l, int r)
    {
        const auto &a = left_.fields[l];
        const auto &b = right_.fields[r];
        if (a.key != b.key) return 1000000;
        if (a.type != b.type) return 3;
        return equivalent(l, r) ? 0 : 2;
    }

    Row row(int l, int r, bool uncertain)
    {
        Row result;
        result.left = l;
        result.right = r;
        result.uncertain = uncertain;
        const Field *a = l < 0 ? nullptr : &left_.fields[l];
        const Field *b = r < 0 ? nullptr : &right_.fields[r];
        result.children = siblings(a ? a->children : QVector<int>(), b ? b->children : QVector<int>());
        if (!a) result.state = State::RightOnly;
        else if (!b) result.state = State::LeftOnly;
        else if (a->type != b->type) result.state = State::TypeChanged;
        else if (!(a->container && b->container) && !equal_(l, r)) result.state = State::Changed;
        result.valueState = result.state;
        if (result.state == State::Equal && std::any_of(result.children.cbegin(), result.children.cend(),
                 [](const Row &child) { return child.state != State::Equal; })) result.state = State::Changed;
        return result;
    }

public:
    Comparison(const Packet &left, const Packet &right, const ValueEqual &equal) :
        left_(left), right_(right), equal_(equal) {}

    QVector<Row> siblings(const QVector<int> &left, const QVector<int> &right)
    {
        QVector<Row> rows;
        QHash<QString, int> occurrences;
        for (int i : left) ++occurrences[left_.fields[i].key];
        for (int i : right) ++occurrences[right_.fields[i].key];
        auto append = [&](int l, int r, bool fallback = false) {
            bool ambiguous = l >= 0 && r >= 0 && cost(l, r) != 0 &&
                    occurrences.value(left_.fields[l].key) > 2;
            rows.append(row(l, r, fallback || ambiguous || (l >= 0 && r >= 0 && equality_budget_ == 0)));
        };
        const int n = static_cast<int>(left.size()), m = static_cast<int>(right.size());
        // Bound the sequence alignment memory and work even for hostile repeat counts.
        if (static_cast<qint64>(n + 1) * (m + 1) <= 65536) {
            QVector<int> scores((n + 1) * (m + 1));
            auto score = [&](int i, int j) -> int & { return scores[i * (m + 1) + j]; };
            for (int i = n; i >= 0; --i) {
                for (int j = m; j >= 0; --j) {
                    if (i == n) score(i, j) = 2 * (m - j);
                    else if (j == m) score(i, j) = 2 * (n - i);
                    else score(i, j) = std::min({cost(left[i], right[j]) + score(i + 1, j + 1),
                                               2 + score(i + 1, j), 2 + score(i, j + 1)});
                }
            }
            int i = 0, j = 0;
            while (i < n || j < m) {
                if (i < n && j < m && score(i, j) == cost(left[i], right[j]) + score(i + 1, j + 1)) {
                    append(left[i++], right[j++]);
                } else if (j < m && score(i, j) == 2 + score(i, j + 1)) {
                    append(-1, right[j++]);
                } else append(left[i++], -1);
            }
        } else {
            // Ordered key queues keep the fallback linear; never search an unbounded suffix.
            QHash<QString, QVector<int>> positions;
            QHash<QString, int> cursors;
            for (int j = 0; j < m; ++j) positions[right_.fields[right[j]].key].append(j);
            int j = 0;
            for (int l : left) {
                const auto &key = left_.fields[l].key;
                const auto &indices = positions[key];
                int &cursor = cursors[key];
                while (cursor < indices.size() && indices[cursor] < j) ++cursor;
                if (cursor == indices.size()) { append(l, -1); continue; }
                int match = indices[cursor++];
                while (j < match) append(-1, right[j++]);
                append(l, right[j++], true);
            }
            while (j < m) append(-1, right[j++]);
        }
        return rows;
    }
};
}

QVector<Row> compare(const Packet &left, const Packet &right, const ValueEqual &equal)
{
    return Comparison(left, right, equal).siblings(left.roots, right.roots);
}

QVector<ByteRange> compareBytes(const QByteArray &left, const QByteArray &right)
{
    QVector<ByteRange> ranges;
    const int common = static_cast<int>(std::min(left.size(), right.size()));
    int start = -1;
    for (int i = 0; i <= common; ++i) {
        bool changed = i < common && left[i] != right[i];
        if (changed && start < 0) start = i;
        if (!changed && start >= 0) { ranges.append({start, i - start, State::Changed}); start = -1; }
    }
    if (left.size() > common) ranges.append({common, static_cast<int>(left.size()) - common, State::LeftOnly});
    if (right.size() > common) ranges.append({common, static_cast<int>(right.size()) - common, State::RightOnly});
    return ranges;
}
}
