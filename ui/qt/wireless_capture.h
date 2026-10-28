/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include "capture_file.h"
#include "utils/wireless_analysis.h"
#include <QTimer>

// A private, incrementally populated snapshot. Never installs taps or modifies
// the main display filter, columns, or global protocol-tree visibility.
class WirelessCapture : public QObject
{
    Q_OBJECT
public:
    explicit WirelessCapture(CaptureFile &capture, QObject *parent = nullptr);
    const WirelessAnalysis::Model &model() const { return model_; }
    bool sourceValid() const { return valid_; }
    quint32 scanned() const { return nextFrame_ - 1; }
    quint32 total() const;
    QString error() const { return error_; }
    void refresh();
signals:
    void updated();
private:
    void scan();
    void invalidate();
    CaptureFile &capture_;
    WirelessAnalysis::Model model_;
    QTimer timer_;
    quint32 nextFrame_ = 1;
    bool valid_ = true;
    QString error_;
    nstime_t origin_{};
    bool haveOrigin_ = false;
};
