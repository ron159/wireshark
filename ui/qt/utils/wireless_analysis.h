/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once

#include <QMap>
#include <QVector>
#include <QString>
#include <optional>

namespace WirelessAnalysis {
using Mac = quint64;
QString macString(Mac address);

struct Sample {
    quint32 frame = 0;
    qint64 timeNs = 0; // Since first capture frame, independent of time references.
    Mac bssid = 0, sta = 0;
    quint32 interfaceId = 0;
    int frequency = 0, channel = 0;
    std::optional<double> signalDbm, rateMbps;
    bool retry = false;
    bool retryEligible = false; // Management or data, not control frames.
    bool roamingEligible = false;
};
struct Roam {
    Mac sta = 0, oldBssid = 0, newBssid = 0;
    quint32 oldFrame = 0, newFrame = 0;
    qint64 oldTimeNs = 0, newTimeNs = 0;
    bool crossInterface = false;
    qint64 gapNs() const { return newTimeNs - oldTimeNs; }
};
struct Range {
    qint64 first = 0, last = 0;
    bool contains(qint64 t) const { return t >= first && t <= last; }
};
enum class Group { AccessPoint, Station, Channel };
struct Stats {
    quint64 packets = 0, retryEligible = 0, retries = 0;
    quint64 signalCount = 0, rateCount = 0;
    double signalSum = 0, rateSum = 0;
    std::optional<double> retryPercent() const;
    std::optional<double> signal() const;
    std::optional<double> rate() const;
    void add(const Sample &sample);
};
struct Bucket { qint64 timeNs; Stats stats; };

class Model {
public:
    static constexpr qsizetype SampleLimit = 2000000;
    bool append(const Sample &sample);
    void clear();
    const QVector<Sample> &samples() const { return samples_; }
    QVector<Roam> roaming() const;
    Range extent() const;
    QMap<QString, Stats> health(Group group, Range range) const;
    QVector<Bucket> trend(Group group, const QString &key, Range range, int bins) const;
    static QString groupKey(const Sample &sample, Group group);
    bool limited() const { return limited_; }
private:
    QVector<Sample> samples_;
    quint32 lastFrame_ = 0;
    bool limited_ = false;
};
}
