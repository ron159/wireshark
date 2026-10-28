/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "config.h"
#include "wireless_analysis_dialog.h"
#include "widgets/wireless_trend.h"
#include <QComboBox>
#include <QDialogButtonBox>
#include <QDoubleSpinBox>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSplitter>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <algorithm>
#include <cmath>

using namespace WirelessAnalysis;
namespace {
class StatisticItem : public QTreeWidgetItem {
public:
    using QTreeWidgetItem::QTreeWidgetItem;
    bool operator<(const QTreeWidgetItem &other) const override {
        int column = treeWidget()->sortColumn();
        const auto a = data(column, Qt::UserRole), b = other.data(column, Qt::UserRole);
        if (a.isValid() && b.isValid()) return a.toDouble() < b.toDouble();
        return QTreeWidgetItem::operator<(other);
    }
};
void setMetric(QTreeWidgetItem *item, int column, std::optional<double> value, int precision = 1)
{
    item->setText(column, value ? QString::number(*value, 'f', precision) : QStringLiteral("—"));
    if (value) item->setData(column, Qt::UserRole, *value);
    item->setTextAlignment(column, Qt::AlignRight | Qt::AlignVCenter);
}
}

WirelessAnalysisDialog::WirelessAnalysisDialog(QWidget &parent, CaptureFile &capture, View view) :
    GeometryStateDialog(&parent, Qt::Window), capture_(new WirelessCapture(capture, this)), view_(view)
{
    setAttribute(Qt::WA_DeleteOnClose);
    const bool roaming = view == View::Roaming;
    setObjectName(roaming ? "wirelessRoamingDialog" : "wirelessHealthDialog");
    setWindowTitle(tr("%1 — %2").arg(roaming ? tr("Roaming Analyzer") : tr("Wireless Health"), capture.fileTitle()));
    loadGeometry(1150, 750, roaming ? "RoamingAnalyzer" : "WirelessHealth");
    auto *layout = new QVBoxLayout(this);
    auto *tools = new QHBoxLayout;
    group_ = new QComboBox(this);
    group_->setObjectName("wirelessGroup");
    group_->addItems({tr("Access points (BSSID)"), tr("Stations (STA)"), tr("Channels")});
    if (roaming) {
        group_->hide();
        tools->addWidget(new QLabel(tr("Station:"), this));
        station_ = new QComboBox(this); station_->setObjectName("roamingStation");
        station_->addItem(tr("All stations"), QString());
        tools->addWidget(station_, 1);
        connect(station_, &QComboBox::currentIndexChanged, this, &WirelessAnalysisDialog::rebuild);
    } else {
        tools->addWidget(group_);
        auto *all = new QPushButton(tr("All entities"), this);
        all->setObjectName("wirelessAllEntities"); tools->addWidget(all);
        connect(all, &QPushButton::clicked, this, [this] { selectedKey_.clear(); table_->clearSelection(); updateTrend(); });
        connect(group_, &QComboBox::currentIndexChanged, this, [this] { selectedKey_.clear(); rebuild(); });
    }
    tools->addStretch();
    refresh_ = new QPushButton(tr("Refresh"), this); tools->addWidget(refresh_);
    connect(refresh_, &QPushButton::clicked, capture_, &WirelessCapture::refresh);
    layout->addLayout(tools);
    auto *times = new QHBoxLayout;
    times->addWidget(new QLabel(tr("Time range (s):"), this));
    first_ = new QDoubleSpinBox(this); last_ = new QDoubleSpinBox(this);
    first_->setObjectName("wirelessRangeStart"); last_->setObjectName("wirelessRangeEnd");
    for (auto *spin : {first_, last_}) {
        spin->setDecimals(9); spin->setRange(-9e9, 9e9); spin->setSingleStep(0.1);
        spin->setKeyboardTracking(false); times->addWidget(spin);
        connect(spin, &QDoubleSpinBox::editingFinished, this, [this] { setRange(first_->value(), last_->value()); });
    }
    auto *reset = new QPushButton(tr("All time"), this); reset->setObjectName("wirelessAllTime");
    times->addWidget(reset); times->addStretch();
    connect(reset, &QPushButton::clicked, this, &WirelessAnalysisDialog::resetRange);
    layout->addLayout(times);
    selection_ = new QLabel(this); selection_->setTextFormat(Qt::PlainText); layout->addWidget(selection_);
    table_ = new QTreeWidget(this); table_->setObjectName("wirelessTable");
    table_->setRootIsDecorated(false); table_->setAlternatingRowColors(true);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setUniformRowHeights(true);
    if (roaming) {
        table_->setHeaderLabels({tr("Time (s)"), tr("Station"), tr("Old BSSID"), tr("New BSSID"),
                                tr("Data gap (ms)"), tr("Old packet"), tr("New packet"), tr("Clock source")});
        layout->addWidget(table_, 1);
        auto *navigation = new QHBoxLayout;
        oldPacket_ = new QPushButton(tr("Go to old packet"), this); oldPacket_->setObjectName("roamingOldPacket");
        newPacket_ = new QPushButton(tr("Go to new packet"), this); newPacket_->setObjectName("roamingNewPacket");
        health_ = new QPushButton(tr("Station health…"), this); health_->setObjectName("roamingHealth");
        navigation->addWidget(oldPacket_); navigation->addWidget(newPacket_); navigation->addWidget(health_); navigation->addStretch();
        layout->addLayout(navigation);
        connect(table_, &QTreeWidget::itemSelectionChanged, this, &WirelessAnalysisDialog::updateNavigation);
        auto jump = [this](bool old) {
            if (!capture_->sourceValid() || table_->selectedItems().isEmpty()) return;
            auto *item = table_->selectedItems().first();
            emit goToPacket(item->data(old ? 5 : 6, Qt::UserRole).toUInt());
        };
        connect(oldPacket_, &QPushButton::clicked, this, [jump] { jump(true); });
        connect(newPacket_, &QPushButton::clicked, this, [jump] { jump(false); });
        connect(table_, &QTreeWidget::itemDoubleClicked, this, [jump] { jump(false); });
        connect(health_, &QPushButton::clicked, this, [this] {
            if (table_->selectedItems().isEmpty()) return;
            const auto &event = roams_[table_->selectedItems().first()->data(0, Qt::UserRole + 1).toInt()];
            emit showStationHealth(event.sta, {event.oldTimeNs, event.newTimeNs});
        });
    } else {
        table_->setHeaderLabels({tr("Entity"), tr("Packets"), tr("Retries"), tr("Retry (%)"), tr("Signal (dBm)"), tr("PHY rate (Mb/s)")});
        auto *splitter = new QSplitter(Qt::Vertical, this);
        trend_ = new WirelessTrend(this); trend_->setObjectName("wirelessTrend");
        splitter->addWidget(trend_); splitter->addWidget(table_); splitter->setStretchFactor(0, 3); splitter->setStretchFactor(1, 2);
        layout->addWidget(splitter, 1);
        connect(trend_, &WirelessTrend::rangeSelected, this, &WirelessAnalysisDialog::setRange);
        connect(trend_, &WirelessTrend::resetRequested, this, &WirelessAnalysisDialog::resetRange);
        connect(table_, &QTreeWidget::itemSelectionChanged, this, [this] {
            if (!table_->selectedItems().isEmpty()) selectedKey_ = table_->selectedItems().first()->text(0);
            updateTrend();
        });
    }
    table_->setSortingEnabled(true);
    table_->sortByColumn(0, Qt::AscendingOrder);
    auto *note = new QLabel(roaming
        ? tr("Observed BSSID changes between non-retry data frames. Data gap is not measured application downtime. Cross-interface timestamps require aligned capture clocks.")
        : tr("Signal is measured at the capture location. PHY rate is not throughput. Retry percentage uses captured management/data frames. Drag the chart to focus all three trends; double-click for all time."), this);
    note->setWordWrap(true); layout->addWidget(note);
    status_ = new QLabel(this); status_->setObjectName("wirelessStatus"); status_->setTextFormat(Qt::PlainText); status_->setWordWrap(true);
    layout->addWidget(status_);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Close, this); layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::close);
    redraw_.setSingleShot(true); redraw_.setInterval(200);
    connect(&redraw_, &QTimer::timeout, this, &WirelessAnalysisDialog::rebuild);
    connect(capture_, &WirelessCapture::updated, this, [this] {
        if (!redraw_.isActive()) redraw_.start();
        updateNavigation();
    });
    rebuild();
}
Group WirelessAnalysisDialog::group() const { return static_cast<Group>(group_->currentIndex()); }
Range WirelessAnalysisDialog::range() const
{
    return {static_cast<qint64>(std::round(first_->value() * 1e9)), static_cast<qint64>(std::round(last_->value() * 1e9))};
}
void WirelessAnalysisDialog::setRange(double first, double last)
{
    const auto extent = capture_->model().extent();
    const double low = extent.first / 1e9, high = extent.last / 1e9;
    if (first > last) std::swap(first, last);
    QSignalBlocker a(first_), b(last_);
    first_->setValue(std::clamp(first, low, high)); last_->setValue(std::clamp(last, low, high));
    allTime_ = false; rebuild();
}
void WirelessAnalysisDialog::resetRange() { allTime_ = true; rebuild(); }
void WirelessAnalysisDialog::selectStation(Mac sta, Range selected)
{
    group_->setCurrentIndex(1); selectedKey_ = macString(sta);
    // The new window may still be collecting data. Preserve the requested range.
    allTime_ = false;
    first_->setValue(selected.first / 1e9); last_->setValue(selected.last / 1e9);
    rebuild();
}
void WirelessAnalysisDialog::updateNavigation()
{
    const bool valid = capture_->sourceValid();
    refresh_->setEnabled(valid);
    if (!oldPacket_) return;
    const bool selected = valid && !table_->selectedItems().isEmpty();
    oldPacket_->setEnabled(selected); newPacket_->setEnabled(selected); health_->setEnabled(selected);
}
void WirelessAnalysisDialog::rebuild()
{
    const auto &model = capture_->model();
    if (allTime_) {
        const auto extent = model.extent();
        QSignalBlocker a(first_), b(last_);
        first_->setValue(extent.first / 1e9); last_->setValue(extent.last / 1e9);
    }
    const QSignalBlocker block(table_);
    quint32 selectedFrame = table_->selectedItems().isEmpty() ? 0 : table_->selectedItems().first()->data(6, Qt::UserRole).toUInt();
    table_->setSortingEnabled(false); table_->clear();
    if (view_ == View::Roaming) {
        roams_ = model.roaming();
        const QSignalBlocker stationBlock(station_);
        QString selected = station_->currentData().toString();
        station_->clear(); station_->addItem(tr("All stations"), QString());
        const auto stations = model.health(Group::Station, model.extent());
        for (auto it = stations.cbegin(); it != stations.cend(); ++it) station_->addItem(it.key(), it.key());
        station_->setCurrentIndex(std::max(0, station_->findData(selected)));
        for (qsizetype i = 0; i < roams_.size(); ++i) {
            const auto &event = roams_[i];
            if (!range().contains(event.newTimeNs) || (!selected.isEmpty() && macString(event.sta) != selected)) continue;
            auto *item = new StatisticItem(table_);
            setMetric(item, 0, event.newTimeNs / 1e9, 6);
            item->setData(0, Qt::UserRole + 1, static_cast<int>(i));
            item->setText(1, macString(event.sta)); item->setText(2, macString(event.oldBssid)); item->setText(3, macString(event.newBssid));
            setMetric(item, 4, event.gapNs() / 1e6, 3);
            setMetric(item, 5, event.oldFrame, 0); setMetric(item, 6, event.newFrame, 0);
            item->setText(7, event.crossInterface ? tr("Multiple interfaces") : tr("Same interface"));
            if (event.newFrame == selectedFrame) item->setSelected(true);
        }
        selection_->setText(tr("%1 transitions in range · %2 stations in capture").arg(table_->topLevelItemCount()).arg(stations.size()));
    } else {
        const auto stats = model.health(group(), range());
        for (auto it = stats.cbegin(); it != stats.cend(); ++it) {
            auto *item = new StatisticItem(table_); item->setText(0, it.key());
            const auto &s = it.value();
            setMetric(item, 1, s.packets, 0); setMetric(item, 2, s.retries, 0);
            setMetric(item, 3, s.retryPercent()); setMetric(item, 4, s.signal()); setMetric(item, 5, s.rate());
            item->setToolTip(4, tr("%1 signal measurements").arg(s.signalCount));
            item->setToolTip(5, tr("%1 PHY rate measurements").arg(s.rateCount));
            if (it.key() == selectedKey_) item->setSelected(true);
        }
        updateTrend();
    }
    table_->setSortingEnabled(true);
    for (int col = 0; col < table_->columnCount(); ++col) table_->resizeColumnToContents(col);
    QString status = tr("%1 WLAN frames · %2 / %3 capture packets scanned · independent of the main display filter")
            .arg(model.samples().size()).arg(capture_->scanned()).arg(capture_->total());
    if (!capture_->sourceValid()) status += tr(" · Capture closed or reloaded; snapshot retained, navigation disabled");
    if (model.limited()) status += tr(" · Sample limit reached; results are incomplete");
    if (!capture_->error().isEmpty()) status += QStringLiteral(" · ") + capture_->error();
    status_->setText(status); updateNavigation();
}
void WirelessAnalysisDialog::updateTrend()
{
    if (!trend_) return;
    selection_->setText(selectedKey_.isEmpty() ? tr("All entities in selected group") : tr("Selected: %1").arg(selectedKey_));
    trend_->setData(capture_->model().trend(group(), selectedKey_, range(), 120), range());
}
