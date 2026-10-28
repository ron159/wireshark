/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include "geometry_state_dialog.h"
#include "wireless_capture.h"

class QComboBox;
class QDoubleSpinBox;
class QLabel;
class QPushButton;
class QTreeWidget;
class WirelessTrend;

class WirelessAnalysisDialog : public GeometryStateDialog
{
    Q_OBJECT
public:
    enum class View { Roaming, Health };
    WirelessAnalysisDialog(QWidget &parent, CaptureFile &capture, View view);
    void selectStation(WirelessAnalysis::Mac sta, WirelessAnalysis::Range range);
signals:
    void goToPacket(unsigned frame);
    void showStationHealth(WirelessAnalysis::Mac sta, WirelessAnalysis::Range range);
private:
    void rebuild();
    void updateTrend();
    void setRange(double first, double last);
    void resetRange();
    void updateNavigation();
    WirelessAnalysis::Range range() const;
    WirelessAnalysis::Group group() const;
    WirelessCapture *capture_;
    View view_;
    QComboBox *group_, *station_ = nullptr;
    QDoubleSpinBox *first_, *last_;
    QLabel *status_, *selection_;
    QTreeWidget *table_;
    WirelessTrend *trend_ = nullptr;
    QPushButton *oldPacket_ = nullptr, *newPacket_ = nullptr, *health_ = nullptr, *refresh_;
    QTimer redraw_;
    bool allTime_ = true;
    QString selectedKey_;
    QVector<WirelessAnalysis::Roam> roams_;
};
