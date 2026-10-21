/** @file
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <config.h>
#include "packet_comparison_dialog.h"
#include "capture_file.h"
#include "widgets/hex_data_source_view.h"
#include <epan/epan_dissect.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/tvbuff.h>
#include <file.h>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileInfo>
#include <QFontDatabase>
#include <QHeaderView>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPushButton>
#include <QScrollBar>
#include <QSplitter>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <algorithm>
#include <limits>

using namespace PacketComparison;

namespace {
class ComparisonByteView : public HexDataSourceView {
public:
    using HexDataSourceView::HexDataSourceView;
    std::function<void()> refreshAnnotations;
protected:
    void resizeEvent(QResizeEvent *event) override {
        HexDataSourceView::resizeEvent(event);
        if (refreshAnnotations) refreshAnnotations();
    }
    void showEvent(QShowEvent *event) override {
        HexDataSourceView::showEvent(event);
        if (refreshAnnotations) refreshAnnotations();
    }
};

// All borrowed field values stay inside these two scoped dissections.
struct Dissection {
    wtap_rec rec;
    epan_dissect_t edt;
    QVector<const fvalue_t *> values;
    bool initialized = false;
    Dissection() { wtap_rec_init(&rec, DEFAULT_INIT_BUFFER_SIZE_2048); }
    ~Dissection() { if (initialized) epan_dissect_cleanup(&edt); wtap_rec_cleanup(&rec); }
};

bool snapshot(capture_file *cf, unsigned number, Dissection &d, Packet &packet, QString &error)
{
    frame_data *frame = frame_data_sequence_find(cf->provider.frames, number);
    if (!frame || !cf_read_record(cf, frame, &d.rec)) {
        error = PacketComparisonDialog::tr("Could not read packet %1.").arg(number);
        return false;
    }
    if (frame->cap_len > 64 * 1024 * 1024 || frame->cap_len > ws_buffer_length(&d.rec.data)) {
        error = PacketComparisonDialog::tr("Packet data sources exceed the 64 MiB comparison limit.");
        return false;
    }
    packet.bytes = QByteArray(reinterpret_cast<const char *>(ws_buffer_start_ptr(&d.rec.data)), frame->cap_len);
    epan_dissect_init(&d.edt, cf->epan, true, true);
    d.initialized = true;
    // No column priming or filling: comparison must not change dynamic columns.
    epan_dissect_run(&d.edt, cf->cd_t, &d.rec, frame, nullptr);
    packet.number = number;
    packet.reportedLength = frame->pkt_len;
    QHash<tvbuff_t *, QString> sources;
    qint64 total = 0;
    for (GSList *entry = d.edt.pi.data_src; entry; entry = entry->next) {
        auto *source = static_cast<struct data_source *>(entry->data);
        tvbuff_t *tvb = get_data_source_tvb(source);
        if (!tvb) continue;
        unsigned length = packet.sources.isEmpty() ? frame->cap_len : tvb_captured_length(tvb);
        total += length;
        if (total > 64 * 1024 * 1024) {
            error = PacketComparisonDialog::tr("Packet data sources exceed the 64 MiB comparison limit.");
            return false;
        }
        QString name = packet.sources.isEmpty() ? QStringLiteral("Frame") : QString::fromUtf8(get_data_source_name(source));
        QString unique = name;
        int occurrence = 2;
        while (std::any_of(packet.sources.cbegin(), packet.sources.cend(),
                          [&](const Packet::Source &s) { return s.name == unique; }))
            unique = name + QStringLiteral(" [%1]").arg(occurrence++);
        QByteArray bytes;
        if (packet.sources.isEmpty()) bytes = packet.bytes;
        else if (length) bytes = QByteArray(reinterpret_cast<const char *>(tvb_get_ptr(tvb, 0, length)), length);
        packet.sources.append({unique, bytes, packet.sources.isEmpty() ? frame->pkt_len : tvb_reported_length(tvb)});
        sources.insert(tvb, unique);
    }
    if (packet.sources.isEmpty()) packet.sources.append({QStringLiteral("Frame"), packet.bytes, frame->pkt_len});
    bool limit = false;
    std::function<QVector<int>(proto_node *, int)> fields = [&](proto_node *node, int depth) {
        QVector<int> indices;
        for (; node; node = node->next) {
            if (packet.fields.size() >= 50000 || depth > 256) { limit = true; break; }
            const field_info *info = node->finfo;
            if (!info || !info->hfinfo) continue;
            Field field;
            field.key = QString::fromUtf8(info->hfinfo->abbrev);
            field.label = QString::fromUtf8(info->hfinfo->name);
            field.type = info->hfinfo->type;
            field.container = field.type == FT_NONE || field.type == FT_PROTOCOL;
            field.generated = FI_GET_FLAG(info, FI_GENERATED);
            // Wireshark's relative TCP fields have wire spans but hold session-derived
            // values. The corresponding *_raw fields remain visible by default.
            if (field.key == QStringLiteral("tcp.seq") || field.key == QStringLiteral("tcp.ack"))
                field.generated = true;
            field.metadata = field.key.startsWith(QStringLiteral("frame.")) &&
                    field.key != QStringLiteral("frame.len") && field.key != QStringLiteral("frame.cap_len") &&
                    field.key != QStringLiteral("frame.encap_type");
            char label[ITEM_LABEL_LENGTH];
            size_t offset = 0;
            proto_item_fill_label(info, label, &offset);
            field.value = field.container ? QString::fromUtf8(label) : QString::fromUtf8(label + offset);
            if (!field.generated && info->ds_tvb) {
                field.source = sources.value(tvb_get_ds_tvb(info->ds_tvb));
                field.start = info->start;
                field.length = info->length;
            }
            int index = static_cast<int>(packet.fields.size());
            packet.fields.append(field);
            d.values.append(info->value);
            indices.append(index);
            auto children = fields(node->first_child, depth + 1);
            packet.fields[index].children = std::move(children);
        }
        return indices;
    };
    packet.roots = fields(d.edt.tree->first_child, 0);
    if (limit) error = PacketComparisonDialog::tr("The protocol tree exceeds the comparison limit (50,000 fields or 256 levels).");
    return !limit;
}
}

PacketComparisonDialog *PacketComparisonDialog::create(QWidget *parent, CaptureFile &capture,
                                                      unsigned left, unsigned right, QString &error)
{
    capture_file *cf = capture.capFile();
    error.clear();
    if (!cf || cf->read_lock || cf->state == FILE_READ_PENDING) {
        error = tr("The capture file is busy. Try again after processing finishes.");
        return nullptr;
    }
    Dissection a, b;
    Packet l, r;
    if (!snapshot(cf, left, a, l, error) || !snapshot(cf, right, b, r, error)) return nullptr;
    auto rows = compare(l, r, [&](int i, int j) {
        const auto *av = a.values[i], *bv = b.values[j];
        if (!av || !bv) return av == bv;
        return fvalue_equal(av, bv);
    });
    auto *dialog = new PacketComparisonDialog(parent, std::move(l), std::move(r), std::move(rows), capture.fileName());
    connect(&capture, &CaptureFile::captureEvent, dialog, [dialog](CaptureEvent event) {
        if ((event.captureContext() == CaptureEvent::File && event.eventType() == CaptureEvent::Closing) ||
            (event.captureContext() == CaptureEvent::Reload && event.eventType() == CaptureEvent::Started))
            dialog->invalidateSource();
    });
    return dialog;
}

PacketComparisonDialog::PacketComparisonDialog(QWidget *parent, Packet left, Packet right,
                                               QVector<Row> rows, const QString &filename) :
    QDialog(parent, Qt::Window), left_(std::move(left)), right_(std::move(right)), rows_(std::move(rows))
{
    setAttribute(Qt::WA_DeleteOnClose);
    setObjectName(QStringLiteral("packetComparisonDialog"));
    setWindowTitle(tr("Compare Packets — %1").arg(QFileInfo(filename).fileName()));
    resize(1200, 800);
    auto *layout = new QVBoxLayout(this);
    source_status_ = new QLabel(tr("Snapshot: %1").arg(filename), this);
    source_status_->setTextFormat(Qt::PlainText);
    layout->addWidget(source_status_);
    auto *tools = new QHBoxLayout;
    auto button = [&](const QString &text, auto callback) {
        auto *b = new QPushButton(text, this);
        tools->addWidget(b);
        connect(b, &QPushButton::clicked, this, callback);
        return b;
    };
    button(tr("Swap"), &PacketComparisonDialog::swapPackets)->setObjectName(QStringLiteral("comparisonSwap"));
    button(tr("Previous difference"), [this] { navigate(-1); });
    button(tr("Next difference"), [this] { navigate(1); })->setObjectName(QStringLiteral("comparisonNext"));
    go_left_ = button(tr("Go to left packet"), [this] { emit goToPacket(left_.number); });
    go_right_ = button(tr("Go to right packet"), [this] { emit goToPacket(right_.number); });
    button(tr("Copy result"), &PacketComparisonDialog::copyResult);
    tools->addStretch();
    layout->addLayout(tools);
    auto *options = new QHBoxLayout;
    auto checkbox = [&](const QString &text, const QString &name, bool checked) {
        auto *c = new QCheckBox(text, this);
        c->setObjectName(name);
        c->setChecked(checked);
        options->addWidget(c);
        connect(c, &QCheckBox::toggled, this, &PacketComparisonDialog::rebuildTree);
        return c;
    };
    only_differences_ = checkbox(tr("Only differences"), QStringLiteral("comparisonOnlyDifferences"), true);
    generated_ = checkbox(tr("Generated fields"), QStringLiteral("comparisonGenerated"), false);
    generated_->setToolTip(tr("Generated values can depend on conversation state and relative sequence numbers."));
    all_fields_ = checkbox(tr("Capture metadata"), QStringLiteral("comparisonMetadata"), false);
    dynamic_ = checkbox(tr("Ignore dynamic fields"), QStringLiteral("comparisonDynamic"), false);
    dynamic_->setToolTip(QStringLiteral("ip.id, ip.checksum, tcp.seq, tcp.seq_raw, tcp.ack, tcp.ack_raw, tcp.checksum, udp.checksum"));
    auto *rules = new QPushButton(tr("Ignore rules…"), this);
    options->addWidget(rules);
    connect(rules, &QPushButton::clicked, this, [this] {
        QStringList keys = ignored_.values(); keys.sort();
        bool ok = false;
        QString input = QInputDialog::getText(this, tr("Ignore rules"),
             tr("Exact field abbreviations, separated by commas. Empty the list to reset. Raw byte differences remain visible."),
             QLineEdit::Normal, keys.join(QStringLiteral(", ")), &ok);
        if (!ok) return;
        ignored_.clear();
        for (const auto &key : input.split(',')) if (!key.trimmed().isEmpty()) ignored_.insert(key.trimmed());
        rebuildTree();
    });
    options->addStretch();
    layout->addLayout(options);
    search_ = new QLineEdit(this);
    search_->setPlaceholderText(tr("Find a field or value…"));
    search_->setClearButtonEnabled(true);
    connect(search_, &QLineEdit::textChanged, this, &PacketComparisonDialog::rebuildTree);
    layout->addWidget(search_);
    auto *splitter = new QSplitter(Qt::Vertical, this);
    tree_ = new QTreeWidget(splitter);
    tree_->setObjectName(QStringLiteral("comparisonTree"));
    tree_->setColumnCount(4);
    tree_->setUniformRowHeights(true);
    tree_->setSelectionBehavior(QAbstractItemView::SelectRows);
    tree_->header()->setSectionResizeMode(QHeaderView::Interactive);
    tree_->setColumnWidth(0, 360); tree_->setColumnWidth(1, 270); tree_->setColumnWidth(2, 270);
    connect(tree_, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem *item) { selectField(item); });
    tree_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(tree_, &QWidget::customContextMenuRequested, this, [this](const QPoint &pos) {
        auto *item = tree_->itemAt(pos);
        if (!item) return;
        QString key = item->data(0, Qt::UserRole + 2).toString();
        QMenu menu(this);
        menu.addAction(tr("Ignore field %1").arg(key), this, [this, key] { ignored_.insert(key); rebuildTree(); });
        menu.exec(tree_->viewport()->mapToGlobal(pos));
    });
    auto *bytes_panel = new QWidget(splitter);
    auto *bytes_layout = new QVBoxLayout(bytes_panel);
    source_ = new QComboBox(bytes_panel);
    source_->setObjectName(QStringLiteral("comparisonSource"));
    for (const auto &s : left_.sources) source_->addItem(s.name);
    for (const auto &s : right_.sources) if (source_->findText(s.name) < 0) source_->addItem(s.name);
    source_->setToolTip(tr("Data sources are paired by name and occurrence. Select Frame for original bytes."));
    bytes_layout->addWidget(source_);
    bytes_container_ = new QWidget(bytes_panel);
    new QHBoxLayout(bytes_container_);
    bytes_layout->addWidget(bytes_container_, 1);
    byte_status_ = new QLabel(bytes_panel);
    byte_status_->setWordWrap(true);
    bytes_layout->addWidget(byte_status_);
    connect(source_, &QComboBox::currentIndexChanged, this, &PacketComparisonDialog::rebuildBytes);
    splitter->setSizes({450, 250});
    layout->addWidget(splitter, 1);
    summary_ = new QLabel(this);
    summary_->setObjectName(QStringLiteral("comparisonSummary"));
    layout->addWidget(summary_);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::close);
    layout->addWidget(buttons);
    rebuildBytes();
    rebuildTree();
}

QString PacketComparisonDialog::stateText(State state) const
{
    switch (state) {
    case State::Changed: return tr("Changed");
    case State::LeftOnly: return tr("Left only");
    case State::RightOnly: return tr("Right only");
    case State::TypeChanged: return tr("Type changed");
    default: return tr("Equal");
    }
}

void PacketComparisonDialog::rebuildTree()
{
    tree_->clear();
    differences_.clear();
    tree_->setHeaderLabels({tr("Field"), tr("Left #%1").arg(left_.number), tr("Right #%1").arg(right_.number), tr("State")});
    const QSet<QString> dynamic = {"ip.id", "ip.checksum", "tcp.seq", "tcp.seq_raw", "tcp.ack", "tcp.ack_raw", "tcp.checksum", "udp.checksum"};
    int changed = 0, leftOnly = 0, rightOnly = 0, ignored = 0;
    std::function<bool(const Row &, QTreeWidgetItem *, bool)> add = [&](const Row &row, QTreeWidgetItem *parent, bool inheritedIgnore) {
        const Field *l = row.left < 0 ? nullptr : &left_.fields[row.left];
        const Field *r = row.right < 0 ? nullptr : &right_.fields[row.right];
        const auto &f = l ? *l : *r;
        bool suppress = inheritedIgnore || ignored_.contains(f.key) ||
            (dynamic_->isChecked() && dynamic.contains(f.key)) ||
            (!generated_->isChecked() && ((l && l->generated) || (r && r->generated))) ||
            (!all_fields_->isChecked() && ((l && l->metadata) || (r && r->metadata)));
        auto *item = new QTreeWidgetItem(parent);
        item->setText(0, QStringLiteral("%1 (%2)").arg(f.label, f.key));
        item->setText(1, l ? l->value : QStringLiteral("—"));
        item->setText(2, r ? r->value : QStringLiteral("—"));
        item->setData(0, Qt::UserRole, row.left);
        item->setData(0, Qt::UserRole + 1, row.right);
        item->setData(0, Qt::UserRole + 2, f.key);
        bool childDifference = false, childVisible = false;
        for (const auto &child : row.children) {
            bool differs = add(child, item, suppress);
            childDifference |= differs;
        }
        for (int i = 0; i < item->childCount(); ++i) childVisible |= !item->child(i)->isHidden();
        bool own = row.valueState != State::Equal && !suppress;
        bool differs = own || childDifference;
        bool match = search_->text().isEmpty();
        for (int i = 0; i < 3; ++i) match |= item->text(i).contains(search_->text(), Qt::CaseInsensitive);
        item->setHidden((only_differences_->isChecked() && !differs) || (!match && !childVisible));
        QString state = suppress ? tr("Ignored") : stateText(own ? row.valueState : childDifference ? State::Changed : State::Equal);
        if (!suppress && row.valueState == State::LeftOnly && right_.bytes.size() < right_.reportedLength)
            state = tr("Unavailable on the right (truncated)");
        if (!suppress && row.valueState == State::RightOnly && left_.bytes.size() < left_.reportedLength)
            state = tr("Unavailable on the left (truncated)");
        if (row.uncertain) state += tr(" · uncertain match");
        item->setText(3, state);
        for (int i = 0; i < 4; ++i) {
            item->setToolTip(i, item->text(i));
        }
        QFont statusFont = item->font(3);
        statusFont.setBold(differs);
        item->setFont(3, statusFont);
        if (row.valueState != State::Equal && !f.container) {
            if (suppress) ++ignored;
            else if (row.valueState == State::LeftOnly) ++leftOnly;
            else if (row.valueState == State::RightOnly) ++rightOnly;
            else ++changed;
        }
        if (own && !item->isHidden() && !f.container) differences_.append(item);
        if (!item->isHidden()) item->setExpanded(true);
        return differs;
    };
    for (const auto &row : rows_) add(row, tree_->invisibleRootItem(), false);
    summary_->setText(tr("Changed: %1 · Left only: %2 · Right only: %3 · Ignored differences: %4 · Custom rules: %5")
                      .arg(changed).arg(leftOnly).arg(rightOnly).arg(ignored).arg(ignored_.size()));
    if (!differences_.isEmpty()) tree_->setCurrentItem(differences_.first());
}

void PacketComparisonDialog::rebuildBytes()
{
    delete left_bytes_; delete right_bytes_;
    QString name = source_->currentText();
    const Packet::Source *l = nullptr, *r = nullptr;
    for (const auto &s : left_.sources) if (s.name == name) l = &s;
    for (const auto &s : right_.sources) if (s.name == name) r = &s;
    left_bytes_ = new ComparisonByteView(l ? l->bytes : QByteArray(), PACKET_CHAR_ENC_CHAR_ASCII, bytes_container_);
    right_bytes_ = new ComparisonByteView(r ? r->bytes : QByteArray(), PACKET_CHAR_ENC_CHAR_ASCII, bytes_container_);
    left_bytes_->setObjectName(QStringLiteral("comparisonLeftBytes"));
    right_bytes_->setObjectName(QStringLiteral("comparisonRightBytes"));
    const QFont mono = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    left_bytes_->setMonospaceFont(mono); right_bytes_->setMonospaceFont(mono);
    bytes_container_->layout()->addWidget(left_bytes_); bytes_container_->layout()->addWidget(right_bytes_);
    const QByteArray lb = l ? l->bytes : QByteArray(), rb = r ? r->bytes : QByteArray();
    int rangeCount = 0;
    bool previous = false;
    const int common = static_cast<int>(std::min(lb.size(), rb.size()));
    for (int i = 0; i < common; ++i) {
        bool changed = lb[i] != rb[i];
        if (changed && !previous) ++rangeCount;
        previous = changed;
    }
    if (lb.size() != rb.size()) ++rangeCount;
    const unsigned lreported = l ? l->reportedLength : 0, rreported = r ? r->reportedLength : 0;
    auto annotate = [this, lb, rb, lreported, rreported](HexDataSourceView *view, bool left) {
        auto visible = view->visibleByteRange();
        QVector<HexDataSourceView::ByteViewAnnotation> annotations;
        QColor highlight = palette().color(QPalette::Highlight); highlight.setAlpha(75);
        // Compare only visible bytes for drawing: dense changes never allocate
        // millions of annotation objects or slow every painted byte to O(file size).
        for (const auto &range : compareBytes(lb.mid(visible.first, visible.second), rb.mid(visible.first, visible.second))) {
            if ((left && range.state == State::RightOnly) || (!left && range.state == State::LeftOnly)) continue;
            QString comment = stateText(range.state);
            if (range.state == State::LeftOnly && rb.size() < rreported && static_cast<unsigned>(range.start + visible.first) < rreported)
                comment = tr("Unavailable on the right (truncated)");
            if (range.state == State::RightOnly && lb.size() < lreported && static_cast<unsigned>(range.start + visible.first) < lreported)
                comment = tr("Unavailable on the left (truncated)");
            annotations.append({range.start + visible.first, range.length, highlight, comment});
        }
        view->setAnnotations(annotations);
    };
    for (auto *view : {left_bytes_, right_bytes_}) {
        const bool left = view == left_bytes_;
        static_cast<ComparisonByteView *>(view)->refreshAnnotations = [annotate, view, left] { annotate(view, left); };
        connect(view->verticalScrollBar(), &QScrollBar::valueChanged, view, [annotate, view, left] { annotate(view, left); });
        connect(view->verticalScrollBar(), &QScrollBar::rangeChanged, view, [annotate, view, left] { annotate(view, left); });
        connect(view, &HexDataSourceView::byteViewSettingsChanged, view, [annotate, view, left] { annotate(view, left); });
        annotate(view, left);
        view->show();
    }
    byte_status_->setText(tr("Offset comparison · %1 changed ranges · Left: %2/%3 captured bytes · Right: %4/%5 captured bytes. Field ignore rules do not hide byte differences.")
          .arg(rangeCount).arg(l ? l->bytes.size() : 0).arg(l ? l->reportedLength : 0)
          .arg(r ? r->bytes.size() : 0).arg(r ? r->reportedLength : 0));
    if ((l && l->bytes.size() < l->reportedLength) || (r && r->bytes.size() < r->reportedLength))
        byte_status_->setText(byte_status_->text() + tr(" Truncated capture: uncaptured bytes cannot be compared."));
    if (!l || !r) byte_status_->setText(byte_status_->text() + tr(" This data source is absent on one side."));
    auto selectByte = [this](bool left, int offset) {
        const auto &packet = left ? left_ : right_;
        QTreeWidgetItemIterator it(tree_);
        QTreeWidgetItem *best = nullptr;
        int length = std::numeric_limits<int>::max();
        for (; *it; ++it) {
            int index = (*it)->data(0, Qt::UserRole + (left ? 0 : 1)).toInt();
            if (index < 0 || (*it)->isHidden()) continue;
            const auto &f = packet.fields[index];
            if (f.source == source_->currentText() && offset >= f.start && offset - f.start < f.length && f.length < length) {
                best = *it; length = f.length;
            }
        }
        if (best) { tree_->setCurrentItem(best); tree_->scrollToItem(best); }
    };
    connect(left_bytes_, &HexDataSourceView::byteSelected, this, [selectByte](int offset) { selectByte(true, offset); });
    connect(right_bytes_, &HexDataSourceView::byteSelected, this, [selectByte](int offset) { selectByte(false, offset); });
    selectField(tree_->currentItem());
}

void PacketComparisonDialog::selectField(QTreeWidgetItem *item)
{
    if (!left_bytes_ || !right_bytes_) return;
    auto mark = [&](const Packet &packet, HexDataSourceView *view, int role) {
        view->unmarkField();
        if (!item) return;
        int index = item->data(0, role).toInt();
        if (index < 0) return;
        const auto &f = packet.fields[index];
        if (f.source == source_->currentText() && f.start >= 0 && f.length > 0)
            view->markField(f.start, f.length);
    };
    mark(left_, left_bytes_, Qt::UserRole); mark(right_, right_bytes_, Qt::UserRole + 1);
}

void PacketComparisonDialog::navigate(int direction)
{
    if (differences_.isEmpty()) return;
    qsizetype index = differences_.indexOf(tree_->currentItem());
    index = (index + direction + differences_.size()) % differences_.size();
    tree_->setCurrentItem(differences_[index]); tree_->scrollToItem(differences_[index]);
}

void PacketComparisonDialog::swapPackets()
{
    std::swap(left_, right_);
    std::function<void(QVector<Row> &)> swap = [&](QVector<Row> &rows) {
        for (auto &row : rows) {
            std::swap(row.left, row.right);
            auto state = [](State value) { return value == State::LeftOnly ? State::RightOnly : value == State::RightOnly ? State::LeftOnly : value; };
            row.state = state(row.state); row.valueState = state(row.valueState);
            swap(row.children);
        }
    };
    swap(rows_);
    rebuildTree(); rebuildBytes();
}

void PacketComparisonDialog::copyResult()
{
    QStringList lines{tr("Packet comparison: #%1 ↔ #%2").arg(left_.number).arg(right_.number), summary_->text(), byte_status_->text()};
    QStringList rules = ignored_.values(); rules.sort();
    lines << tr("Ignore rules") + QStringLiteral(": ") + rules.join(QStringLiteral(", "));
    for (auto *option : {dynamic_, generated_, all_fields_})
        lines << QStringLiteral("%1: %2").arg(option->text()).arg(option->isChecked() ? 1 : 0);
    QTreeWidgetItemIterator it(tree_);
    for (; *it; ++it) {
        if ((*it)->isHidden()) continue;
        lines << QStringList{(*it)->text(0), (*it)->text(1), (*it)->text(2), (*it)->text(3)}.join('\t');
    }
    QApplication::clipboard()->setText(lines.join('\n'));
}

void PacketComparisonDialog::invalidateSource()
{
    source_status_->setText(tr("Source closed or reloaded. This snapshot remains available."));
    go_left_->setEnabled(false); go_right_->setEnabled(false);
}
