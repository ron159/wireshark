/*
 * Pure packet-comparison regressions. No capture engine or GUI is required.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "ui/qt/utils/packet_comparison.h"

#include <QElapsedTimer>
#include <QSet>

#include <cstdio>

using namespace PacketComparison;

namespace {

int failures = 0;

void check(bool condition, const char *message)
{
    if (!condition) {
        fprintf(stderr, "FAIL: %s\n", message);
        failures++;
    }
}

struct Fixture {
    Packet packet;
    QVector<QString> typed_values;

    int add(const QString &key, const QString &display, const QString &typed,
            int type = 1, int parent = -1, bool container = false)
    {
        Field field;
        field.key = key;
        field.label = key + QStringLiteral(": ") + display;
        field.value = display;
        field.source = QStringLiteral("Frame");
        field.type = type;
        field.container = container;
        const int index = static_cast<int>(packet.fields.size());
        packet.fields.append(field);
        typed_values.append(typed);
        if (parent < 0) {
            packet.roots.append(index);
        } else {
            packet.fields[parent].children.append(index);
        }
        return index;
    }
};

QVector<Row> run(const Fixture &left, const Fixture &right, int *calls = nullptr)
{
    return compare(left.packet, right.packet, [&](int li, int ri) {
        if (calls) (*calls)++;
        const bool valid = li >= 0 && li < left.typed_values.size() &&
                           ri >= 0 && ri < right.typed_values.size();
        check(valid, "typed equality receives valid snapshot indices");
        return valid && left.typed_values[li] == right.typed_values[ri];
    });
}

const Row *findRow(const QVector<Row> &rows, int left, int right)
{
    for (const Row &row : rows) {
        if (row.left == left && row.right == right) {
            return &row;
        }
        if (const Row *found = findRow(row.children, left, right)) {
            return found;
        }
    }
    return nullptr;
}

void checkState(const QVector<Row> &rows, int left, int right, State expected, const char *message)
{
    const Row *row = findRow(rows, left, right);
    check(row && row->state == expected, message);
}

void typedValuesDetermineEquality()
{
    Fixture left, right;
    left.add(QStringLiteral("ip.id"), QStringLiteral("0x002a"), QStringLiteral("42"));
    right.add(QStringLiteral("ip.id"), QStringLiteral("42 (resolved label)"), QStringLiteral("42"));
    auto rows = run(left, right);
    check(rows.size() == 1, "one scalar field produces one row");
    checkState(rows, 0, 0, State::Equal, "different display strings with equal typed values remain equal");

    left.packet.fields[0].value = right.packet.fields[0].value = QStringLiteral("same visible value");
    right.typed_values[0] = QStringLiteral("43");
    rows = run(left, right);
    checkState(rows, 0, 0, State::Changed, "equal display strings cannot hide different typed values");

    right.packet.fields[0].type = 2;
    right.typed_values[0] = left.typed_values[0];
    rows = run(left, right);
    checkState(rows, 0, 0, State::TypeChanged, "the same field identity reports a changed type");
}

void matchingStaysInsideItsParent()
{
    Fixture left, right;
    const int la = left.add(QStringLiteral("layer.a"), {}, {}, 0, -1, true);
    const int lb = left.add(QStringLiteral("layer.b"), {}, {}, 0, -1, true);
    const int ra = right.add(QStringLiteral("layer.a"), {}, {}, 0, -1, true);
    const int rb = right.add(QStringLiteral("layer.b"), {}, {}, 0, -1, true);
    const int lax = left.add(QStringLiteral("shared.field"), QStringLiteral("one"), QStringLiteral("1"), 1, la);
    const int lbx = left.add(QStringLiteral("shared.field"), QStringLiteral("two"), QStringLiteral("2"), 1, lb);
    const int rax = right.add(QStringLiteral("shared.field"), QStringLiteral("two"), QStringLiteral("2"), 1, ra);
    const int rbx = right.add(QStringLiteral("shared.field"), QStringLiteral("one"), QStringLiteral("1"), 1, rb);
    const auto rows = run(left, right);
    check(rows.size() == 2, "two protocol roots remain two protocol rows");
    checkState(rows, lax, rax, State::Changed, "same-key child is compared inside the first parent");
    checkState(rows, lbx, rbx, State::Changed, "same-key child is compared inside the second parent");
    check(!findRow(rows, lax, rbx) && !findRow(rows, lbx, rax), "equal values never match across parents");
    checkState(rows, la, ra, State::Changed, "container aggregates a changed first child");
    checkState(rows, lb, rb, State::Changed, "container aggregates a changed second child");
}

void repeatedFieldsPreserveAnInsertedValue()
{
    Fixture left, right;
    for (const QString &value : {QStringLiteral("A"), QStringLiteral("A"), QStringLiteral("B")}) {
        left.add(QStringLiteral("option"), value, value);
    }
    for (const QString &value : {QStringLiteral("A"), QStringLiteral("X"), QStringLiteral("A"), QStringLiteral("B")}) {
        right.add(QStringLiteral("option"), value, value);
    }
    const auto rows = run(left, right);
    check(rows.size() == 4, "inserting between repeated fields does not shift all later comparisons");
    checkState(rows, -1, 1, State::RightOnly, "the inserted value is represented as a right-only row");
    int equal = 0;
    int previous_left = -1, previous_right = -1;
    for (const Row &row : rows) {
        if (row.left >= 0 && row.right >= 0) {
            check(row.state == State::Equal, "all original duplicate and anchor values stay equal");
            check(row.left > previous_left && row.right > previous_right, "duplicate alignment preserves sibling order");
            previous_left = row.left;
            previous_right = row.right;
            equal++;
        }
    }
    check(equal == 3, "every original repeated field has exactly one match");
}

void repeatedContainersUseTheirChildrenAsAnchors()
{
    Fixture left, right;
    auto record = [](Fixture &fixture, const QString &value) {
        const int parent = fixture.add(QStringLiteral("record"), QStringLiteral("Record"), {}, 0, -1, true);
        fixture.add(QStringLiteral("record.value"), value, value, 1, parent);
        return parent;
    };
    const int la = record(left, QStringLiteral("A"));
    const int lb = record(left, QStringLiteral("B"));
    const int rx = record(right, QStringLiteral("X"));
    const int ra = record(right, QStringLiteral("A"));
    const int rb = record(right, QStringLiteral("B"));
    const auto rows = run(left, right);
    check(rows.size() == 3, "an inserted repeated container produces one extra root");
    checkState(rows, -1, rx, State::RightOnly, "inserted record is right-only instead of changing the first original record");
    checkState(rows, la, ra, State::Equal, "the first repeated record anchors on its typed child value");
    checkState(rows, lb, rb, State::Equal, "the second repeated record anchors on its typed child value");
    checkState(rows, la + 1, ra + 1, State::Equal, "the first anchored record preserves child alignment");
    checkState(rows, lb + 1, rb + 1, State::Equal, "the second anchored record preserves child alignment");
}

void exclusiveFieldsAndContainersRemainVisible()
{
    Fixture left, right;
    const int lp = left.add(QStringLiteral("protocol"), QStringLiteral("left label"), {}, 0, -1, true);
    const int rp = right.add(QStringLiteral("protocol"), QStringLiteral("right label"), {}, 0, -1, true);
    const int common_left = left.add(QStringLiteral("common"), QStringLiteral("7"), QStringLiteral("7"), 1, lp);
    const int common_right = right.add(QStringLiteral("common"), QStringLiteral("7"), QStringLiteral("7"), 1, rp);
    const int only_left = left.add(QStringLiteral("left.field"), QStringLiteral("8"), QStringLiteral("8"), 1, lp);
    const int only_right = right.add(QStringLiteral("right.field"), QStringLiteral("9"), QStringLiteral("9"), 1, rp);
    const auto rows = run(left, right);
    checkState(rows, common_left, common_right, State::Equal, "common child remains equal next to exclusive fields");
    checkState(rows, only_left, -1, State::LeftOnly, "field absent on the right remains visible");
    checkState(rows, -1, only_right, State::RightOnly, "field absent on the left remains visible");
    checkState(rows, lp, rp, State::Changed, "container aggregates exclusive child differences");
    const Row *parent = findRow(rows, lp, rp);
    check(parent && parent->valueState == State::Equal,
          "container aggregate differences remain separate from its own value state");

    left.packet.fields[lp].children = {common_left};
    right.packet.fields[rp].children = {common_right};
    const auto equal_rows = run(left, right);
    checkState(equal_rows, lp, rp, State::Equal, "container labels alone do not change equal children");
}

void largeRepeatedSetsUseBoundedComparison()
{
    constexpr int count = 5000;
    Fixture left, right;
    for (int i = 0; i < count; i++) {
        left.add(QStringLiteral("repeated.option"), QStringLiteral("A"), QStringLiteral("A"));
        if (i == count / 2) {
            right.add(QStringLiteral("repeated.option"), QStringLiteral("X"), QStringLiteral("X"));
        }
        right.add(QStringLiteral("repeated.option"), QStringLiteral("A"), QStringLiteral("A"));
    }
    int calls = 0;
    QElapsedTimer timer;
    timer.start();
    const auto rows = run(left, right, &calls);
    fprintf(stderr, "Large duplicate alignment: %lld ms, %d typed comparisons\n",
            static_cast<long long>(timer.elapsed()), calls);
    check(calls <= 1000000, "large duplicate groups have a bounded typed-comparison budget");
    QSet<int> seen_left, seen_right;
    bool uncertain = false;
    for (const Row &row : rows) {
        if (row.left >= 0) {
            check(!seen_left.contains(row.left), "large fallback never reuses a left field");
            seen_left.insert(row.left);
        }
        if (row.right >= 0) {
            check(!seen_right.contains(row.right), "large fallback never reuses a right field");
            seen_right.insert(row.right);
        }
        if (row.state == State::Equal && row.left >= 0 && row.right >= 0) {
            check(left.typed_values[row.left] == right.typed_values[row.right],
                  "bounded fallback never labels unequal typed values equal");
        }
        uncertain |= row.uncertain;
    }
    check(seen_left.size() == count && seen_right.size() == count + 1,
          "bounded fallback preserves every field on both sides");
    check(uncertain, "bounded duplicate fallback marks uncertain alignment");
}

void recursiveComparisonBudgetMarksUncertainty()
{
    Fixture left, right;
    auto record = [](Fixture &fixture, const QString &last_value) {
        const int parent = fixture.add(QStringLiteral("record"), QStringLiteral("Record"), {}, 0, -1, true);
        for (int child = 0; child < 64; child++) {
            const QString value = child == 63 ? last_value : QStringLiteral("same");
            fixture.add(QStringLiteral("record.field.%1").arg(child), value, value, 1, parent);
        }
    };
    record(right, QStringLiteral("inserted"));
    for (int i = 0; i < 160; i++) {
        record(left, QString::number(i));
        record(right, QString::number(i));
    }
    int calls = 0;
    const auto rows = run(left, right, &calls);
    bool uncertain = false;
    QSet<int> seen_left, seen_right;
    std::function<void(const QVector<Row> &)> visit = [&](const QVector<Row> &children) {
        for (const Row &row : children) {
            uncertain |= row.uncertain;
            if (row.left >= 0) {
                check(!seen_left.contains(row.left), "recursive budget fallback does not reuse left fields");
                seen_left.insert(row.left);
            }
            if (row.right >= 0) {
                check(!seen_right.contains(row.right), "recursive budget fallback does not reuse right fields");
                seen_right.insert(row.right);
            }
            if (row.left >= 0 && row.right >= 0 && row.state == State::Equal &&
                !left.packet.fields[row.left].container && !right.packet.fields[row.right].container) {
                check(left.typed_values[row.left] == right.typed_values[row.right],
                      "recursive budget fallback never invents an equal scalar value");
            }
            visit(row.children);
        }
    };
    visit(rows);
    check(calls <= 1000000, "repeated subtree matching has a global typed-comparison budget");
    check(uncertain, "exhausting the recursive comparison budget marks an uncertain match");
    check(seen_left.size() == left.packet.fields.size() && seen_right.size() == right.packet.fields.size(),
          "recursive budget fallback retains every container and child");
}

void checkRange(const QVector<ByteRange> &ranges, int index, int start, int length, State state, const char *message)
{
    check(index < ranges.size() && ranges[index].start == start &&
          ranges[index].length == length && ranges[index].state == state, message);
}

void byteDifferencesAreOffsetRanges()
{
    const auto changed = compareBytes(QByteArray::fromHex("00112233445566"),
                                      QByteArray::fromHex("00aabb3344cc66"));
    check(changed.size() == 2, "byte comparison omits equal spans and merges adjacent changed bytes");
    checkRange(changed, 0, 1, 2, State::Changed, "adjacent byte differences form one offset range");
    checkRange(changed, 1, 5, 1, State::Changed, "an equal gap separates changed ranges");

    const auto right_tail = compareBytes(QByteArray("abcd"), QByteArray("abcdXYZ"));
    check(right_tail.size() == 1, "an added byte tail produces one range");
    checkRange(right_tail, 0, 4, 3, State::RightOnly, "right-only tail retains its true offset and length");
    const auto left_tail = compareBytes(QByteArray("abcdXYZ"), QByteArray("abcd"));
    checkRange(left_tail, 0, 4, 3, State::LeftOnly, "left-only tail retains its true offset and length");

    const auto mixed = compareBytes(QByteArray("abc123"), QByteArray("abX123zz"));
    check(mixed.size() == 2, "interior replacement and added tail remain distinct");
    checkRange(mixed, 0, 2, 1, State::Changed, "interior replacement uses aligned byte offsets");
    checkRange(mixed, 1, 6, 2, State::RightOnly, "mixed difference retains the added tail");
    check(compareBytes(QByteArray("same"), QByteArray("same")).isEmpty(), "equal bytes produce no difference ranges");
    check(compareBytes({}, {}).isEmpty(), "empty byte arrays produce no difference ranges");
    const auto empty_left = compareBytes({}, QByteArray("abc"));
    checkRange(empty_left, 0, 0, 3, State::RightOnly, "all bytes are right-only when the left packet is empty");
    check(compare(Packet{}, Packet{}, [](int, int) { return false; }).isEmpty(), "empty field snapshots compare without rows");
}

} // namespace

int main()
{
    typedValuesDetermineEquality();
    matchingStaysInsideItsParent();
    repeatedFieldsPreserveAnInsertedValue();
    repeatedContainersUseTheirChildrenAsAnchors();
    exclusiveFieldsAndContainersRemainVisible();
    largeRepeatedSetsUseBoundedComparison();
    recursiveComparisonBudgetMarksUncertainty();
    byteDifferencesAreOffsetRanges();
    fprintf(stderr, "PACKET COMPARISON RESULT: %d failure(s)\n", failures);
    return failures ? 1 : 0;
}
