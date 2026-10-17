/* Dynamic binding for a packet-list custom column.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "packet_list.h"

#include <epan/column.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <ui/preference_utils.h>
#include <QAction>
#include <QApplication>
#include <QHeaderView>
#include <QTimer>

int PacketList::dynamicColumn() const
{
    for (unsigned col = 0; col < prefs.num_cols; col++) {
        if (get_column_custom_dynamic(col)) return col;
    }
    return -1;
}

bool PacketList::dynamicColumnFollowing(int column) const
{
    return get_column_custom_dynamic(column) && !dynamic_column_paused_;
}

QMenu *PacketList::createDynamicColumnMenu(QWidget *parent)
{
    auto menu = new QMenu(tr("Dynamic Decode Column"), parent);
    auto enabled = menu->addAction(tr("Enable"));
    enabled->setCheckable(true);
    connect(enabled, &QAction::triggered, this, &PacketList::setDynamicColumnEnabled);
    auto paused = menu->addAction(tr("Pause Following"));
    paused->setCheckable(true);
    connect(paused, &QAction::triggered, this, &PacketList::setDynamicColumnPaused);
    auto fixed = menu->addAction(tr("Convert to Regular Column"));
    connect(fixed, &QAction::triggered, this, &PacketList::fixDynamicColumn);
    connect(menu, &QMenu::aboutToShow, this, [this, enabled, paused, fixed]() {
        int col = dynamicColumn();
        bool exists = col >= 0;
        bool busy = cap_file_ && cap_file_->read_lock;
        enabled->setChecked(exists);
        enabled->setEnabled(!busy);
        paused->setChecked(dynamic_column_paused_);
        bool sorted = dynamic_column_paused_ && packet_list_proxy_model_->activeSortColumn() == col;
        paused->setEnabled(exists && !busy && !sorted);
        paused->setToolTip(sorted ? tr("Sort another column before resuming following.") : QString());
        fixed->setEnabled(exists && !busy && !dynamic_column_field_.isEmpty());
    });
    return menu;
}

void PacketList::setDynamicColumnEnabled(bool enabled)
{
    if (cap_file_ && cap_file_->read_lock) return;
    int col = dynamicColumn();
    if (enabled == (col >= 0)) return;
    clearDynamicColumnTarget();
    if (enabled) {
        col = column_prefs_add_custom(COL_CUSTOM, "Dynamic Decode", "", -1);
        set_column_custom_dynamic(col, true);
        set_column_display_format(col, COLUMN_DISPLAY_DETAILS);
    } else {
        column_prefs_remove_nth(col);
    }
    columnsChanged();
    prefs_main_write();
}

void PacketList::setDynamicColumnPaused(bool paused)
{
    int col = dynamicColumn();
    if (col < 0 || (cap_file_ && cap_file_->read_lock)) return;
    // Resuming a column used for sorting would silently change the active
    // comparison key. Keep that frozen until another sort is selected.
    if (!paused && packet_list_proxy_model_->activeSortColumn() == col) {
        return;
    }
    dynamic_column_paused_ = paused;
    pending_dynamic_column_field_.clear();
    if (dynamic_column_timer_) dynamic_column_timer_->stop();
    if (cap_file_ && (unsigned)col < cap_file_->cinfo.num_cols) {
        cap_file_->cinfo.columns[col].col_custom_dynamic = !paused;
    }
    refreshDynamicColumn();
}

void PacketList::fixDynamicColumn()
{
    int col = dynamicColumn();
    if (col < 0 || dynamic_column_field_.isEmpty() || (cap_file_ && cap_file_->read_lock)) return;
    set_column_custom_dynamic(col, false);
    set_column_custom_fields(col, dynamic_column_field_.toUtf8().constData());
    set_column_title(col, dynamic_column_field_.toUtf8().constData());
    clearDynamicColumnTarget();
    columnsChanged();
    prefs_main_write();
}

void PacketList::setDynamicColumnField(const QString &field)
{
    if (dynamicColumn() < 0 || dynamic_column_paused_ || field.isEmpty()) return;
    if (!proto_registrar_get_byname(field.toUtf8().constData())) return;
    if (!dynamic_column_timer_) {
        dynamic_column_timer_ = new QTimer(this);
        dynamic_column_timer_->setSingleShot(true);
        dynamic_column_timer_->setInterval(100);
        connect(dynamic_column_timer_, &QTimer::timeout, this, &PacketList::applyDynamicColumnField);
    }
    if (field == dynamic_column_field_) {
        pending_dynamic_column_field_.clear();
        dynamic_column_timer_->stop();
        return;
    }
    if (field == pending_dynamic_column_field_) return;
    pending_dynamic_column_field_ = field;
    dynamic_column_timer_->start();
}

void PacketList::applyDynamicColumnField()
{
    int col = dynamicColumn();
    if (col < 0 || dynamic_column_paused_ || pending_dynamic_column_field_.isEmpty()) return;
    if (!cap_file_ || cap_file_->state == FILE_CLOSED) {
        clearDynamicColumnTarget();
        return;
    }
    // Reading, redissection, sorting and exports can process UI events.
    // Never replace their column plan while the shared capture is locked.
    if (cap_file_->read_lock || !model() || !isEnabled() || QApplication::activeModalWidget()) {
        dynamic_column_timer_->start();
        return;
    }
    QByteArray field = pending_dynamic_column_field_.toUtf8();
    if (col_custom_set_fields(&cap_file_->cinfo, col, field.constData(), get_column_custom_occurrence(col))) {
        dynamic_column_field_ = pending_dynamic_column_field_;
        refreshDynamicColumn();
    }
    pending_dynamic_column_field_.clear();
}

void PacketList::restoreDynamicColumn()
{
    int col = dynamicColumn();
    if (col < 0) {
        clearDynamicColumnTarget();
        return;
    }
    if (!cap_file_ || (unsigned)col >= cap_file_->cinfo.num_cols) return;
    if (!col_custom_set_fields(&cap_file_->cinfo, col, dynamic_column_field_.toUtf8().constData(), get_column_custom_occurrence(col))) {
        clearDynamicColumnTarget();
    }
    cap_file_->cinfo.columns[col].col_custom_dynamic = !dynamic_column_paused_;
    refreshDynamicColumn();
}

void PacketList::clearDynamicColumnTarget()
{
    if (dynamic_column_timer_) dynamic_column_timer_->stop();
    dynamic_column_field_.clear();
    pending_dynamic_column_field_.clear();
    dynamic_column_paused_ = false;
}

void PacketList::refreshDynamicColumn()
{
    int col = dynamicColumn();
    if (col < 0 || !cap_file_ || (unsigned)col >= cap_file_->cinfo.num_cols) return;
    QString title = get_column_title(col);
    if (!dynamic_column_field_.isEmpty()) title += QStringLiteral(": %1").arg(dynamic_column_field_);
    if (dynamic_column_paused_) title += tr(" (paused)");
    auto &item = cap_file_->cinfo.columns[col];
    g_free(item.col_title);
    item.col_title = g_strdup(title.toUtf8().constData());
    // The cache is bounded. Do not issue layoutChanged/dataChanged over the
    // whole model: view bookkeeping can turn a field click into O(N).
    PacketListRecord::invalidateAllRecords();
    emit packet_list_model_->headerDataChanged(Qt::Horizontal, col, col);
    viewport()->update();
    repaintPinnedOverlays();
}
