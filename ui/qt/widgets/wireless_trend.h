/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include "ui/qt/utils/wireless_analysis.h"
#include <QWidget>

// Three metrics on separate y axes and one shared time axis. Empty buckets stay
// empty, and range interaction applies to all metrics together.
class WirelessTrend : public QWidget
{
    Q_OBJECT
public:
    explicit WirelessTrend(QWidget *parent = nullptr);
    void setData(const QVector<WirelessAnalysis::Bucket> &buckets, WirelessAnalysis::Range range);
signals:
    void rangeSelected(double firstSeconds, double lastSeconds);
    void resetRequested();
protected:
    void paintEvent(QPaintEvent *) override;
    void mousePressEvent(QMouseEvent *) override;
    void mouseMoveEvent(QMouseEvent *) override;
    void mouseReleaseEvent(QMouseEvent *) override;
    void mouseDoubleClickEvent(QMouseEvent *) override;
    void wheelEvent(QWheelEvent *) override;
private:
    QRectF plotRect() const;
    double timeAt(double x) const;
    QVector<WirelessAnalysis::Bucket> buckets_;
    WirelessAnalysis::Range range_;
    double dragStart_ = -1, dragEnd_ = -1;
};
