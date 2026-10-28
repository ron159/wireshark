/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "wireless_trend.h"
#include "ui/qt/utils/theme_manager.h"
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QToolTip>
#include <QWheelEvent>
#include <algorithm>

using namespace WirelessAnalysis;
namespace {
std::optional<double> value(const Stats &s, int metric)
{
    return metric == 0 ? s.retryPercent() : (metric == 1 ? s.signal() : s.rate());
}
}
WirelessTrend::WirelessTrend(QWidget *parent) : QWidget(parent)
{
    setMinimumSize(400, 360);
    setMouseTracking(true);
    setAccessibleName(tr("Wireless retry, signal and PHY rate trends"));
    setToolTip(tr("Drag to select a time range. Scroll to zoom. Double-click to show all time."));
    connect(ThemeManager::instance(), &ThemeManager::themeChanged, this, [this] { update(); });
}
void WirelessTrend::setData(const QVector<Bucket> &buckets, Range range)
{
    buckets_ = buckets; range_ = range; update();
}
QRectF WirelessTrend::plotRect() const
{
    return QRectF(76, 28, std::max(1, width() - 96), std::max(1, height() - 60));
}
double WirelessTrend::timeAt(double x) const
{
    const auto r = plotRect();
    const double fraction = std::clamp((x - r.left()) / r.width(), 0.0, 1.0);
    return range_.first / 1e9 + fraction * ((range_.last / 1e9) - (range_.first / 1e9));
}
void WirelessTrend::paintEvent(QPaintEvent *)
{
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.fillRect(rect(), palette().base());
    const auto r = plotRect();
    const QStringList titles{tr("Retry (%)"), tr("Signal (dBm)"), tr("PHY rate (Mb/s)")};
    auto *theme = ThemeManager::instance();
    const QColor colors[]{theme->graphColor(0), theme->graphColor(1), theme->graphColor(2)};
    for (int m = 0; m < 3; ++m) {
        QRectF track(r.left(), r.top() + m * r.height() / 3, r.width(), r.height() / 3 - 32);
        double low = m == 1 ? -100 : 0, high = m == 0 ? 100 : (m == 1 ? -20 : 1);
        bool any = false;
        for (const auto &bucket : buckets_) {
            const auto v = value(bucket.stats, m);
            if (!v) continue;
            any = true;
            low = std::min(low, *v); high = std::max(high, *v);
        }
        painter.setPen(palette().text().color());
        painter.drawText(QRectF(track.left(), track.top() - 22, track.width(), 20), titles[m]);
        for (int tick = 0; tick <= 2; ++tick) {
            const double y = track.bottom() - tick * track.height() / 2;
            auto grid = palette().text().color(); grid.setAlpha(45);
            painter.setPen(grid);
            painter.drawLine(QPointF(track.left(), y), QPointF(track.right(), y));
            painter.setPen(palette().text().color());
            painter.drawText(QRectF(0, y - 10, r.left() - 8, 20), Qt::AlignRight | Qt::AlignVCenter,
                             QString::number(low + tick * (high - low) / 2, 'g', 4));
        }
        if (!any) {
            painter.drawText(track, Qt::AlignCenter, tr("No measurements in this range"));
            continue;
        }
        QPainterPath path;
        bool connected = false;
        for (qsizetype i = 0; i < buckets_.size(); ++i) {
            auto v = value(buckets_[i].stats, m);
            if (!v) { connected = false; continue; }
            const double x = track.left() + (i + 0.5) * track.width() / buckets_.size();
            const double y = track.bottom() - (*v - low) / (high - low) * track.height();
            if (connected) path.lineTo(x, y); else path.moveTo(x, y);
            connected = true;
            painter.setPen(Qt::NoPen); painter.setBrush(colors[m]);
            painter.drawEllipse(QPointF(x, y), 2.5, 2.5);
        }
        painter.setBrush(Qt::NoBrush); painter.setPen(QPen(colors[m], 1.7));
        painter.drawPath(path);
    }
    painter.setPen(palette().text().color());
    for (int i = 0; i <= 4; ++i) {
        const double x = r.left() + i * r.width() / 4;
        painter.drawText(QRectF(x - 45, r.bottom() + 3, 90, 24), Qt::AlignCenter,
                         tr("%1 s").arg(timeAt(x), 0, 'g', 6));
    }
    if (dragStart_ >= 0) {
        QColor shade = palette().highlight().color(); shade.setAlpha(45);
        painter.fillRect(QRectF(QPointF(std::min(dragStart_, dragEnd_), r.top()),
                                QPointF(std::max(dragStart_, dragEnd_), r.bottom())), shade);
    }
}
void WirelessTrend::mousePressEvent(QMouseEvent *e)
{
    if (e->button() == Qt::LeftButton && plotRect().contains(e->position())) {
        dragStart_ = dragEnd_ = e->position().x(); update();
    }
}
void WirelessTrend::mouseMoveEvent(QMouseEvent *e)
{
    if (dragStart_ >= 0) {
        dragEnd_ = std::clamp(e->position().x(), plotRect().left(), plotRect().right()); update(); return;
    }
    if (buckets_.isEmpty() || !plotRect().contains(e->position())) return;
    const auto i = std::clamp(static_cast<qsizetype>((e->position().x() - plotRect().left())
                                  * buckets_.size() / plotRect().width()), qsizetype(0), buckets_.size() - 1);
    const auto &s = buckets_[i].stats;
    auto text = [](std::optional<double> v) { return v ? QString::number(*v, 'f', 2) : tr("Unknown"); };
    QToolTip::showText(e->globalPosition().toPoint(), tr("%1 s\n%2 packets\nRetry: %3%\nSignal: %4 dBm\nPHY rate: %5 Mb/s")
                      .arg(buckets_[i].timeNs / 1e9, 0, 'f', 6).arg(s.packets)
                      .arg(text(s.retryPercent()), text(s.signal()), text(s.rate())), this);
}
void WirelessTrend::mouseReleaseEvent(QMouseEvent *)
{
    if (dragStart_ < 0) return;
    const double a = dragStart_, b = dragEnd_;
    dragStart_ = dragEnd_ = -1; update();
    if (std::abs(a - b) >= 4) emit rangeSelected(timeAt(std::min(a, b)), timeAt(std::max(a, b)));
}
void WirelessTrend::mouseDoubleClickEvent(QMouseEvent *) { emit resetRequested(); }
void WirelessTrend::wheelEvent(QWheelEvent *e)
{
    if (!plotRect().contains(e->position()) || range_.last <= range_.first) return;
    const double center = timeAt(e->position().x());
    const double factor = e->angleDelta().y() > 0 ? 0.7 : 1.4;
    emit rangeSelected(center - (center - range_.first / 1e9) * factor,
                       center + (range_.last / 1e9 - center) * factor);
    e->accept();
}
