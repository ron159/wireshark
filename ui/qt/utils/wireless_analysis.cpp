/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "wireless_analysis.h"
#include <QCoreApplication>
#include <QHash>
#include <algorithm>
#include <cmath>

namespace WirelessAnalysis {
namespace {
constexpr quint64 UnknownBand = quint64(1) << 32;
quint64 identity(const Sample &sample, Group group)
{
    if (group == Group::AccessPoint) return sample.bssid;
    if (group == Group::Station) return sample.sta;
    return sample.frequency ? static_cast<quint64>(sample.frequency)
                            : (sample.channel ? UnknownBand | sample.channel : 0);
}
QString identityLabel(quint64 id, Group group)
{
    if (group != Group::Channel) return id ? macString(id) : QString();
    if (!id) return QCoreApplication::translate("WirelessAnalysis", "Unknown");
    if (id & UnknownBand) return QCoreApplication::translate("WirelessAnalysis", "Channel %1 (band unknown)").arg(id & ~UnknownBand);
    return QString::number(id) + QStringLiteral(" MHz");
}
}
QString macString(Mac address)
{
    QStringList bytes;
    for (int i = 5; i >= 0; --i)
        bytes << QStringLiteral("%1").arg((address >> (8 * i)) & 0xff, 2, 16, QLatin1Char('0'));
    return bytes.join(QLatin1Char(':'));
}

std::optional<double> Stats::retryPercent() const
{
    return retryEligible ? std::optional<double>(100.0 * retries / retryEligible) : std::nullopt;
}
std::optional<double> Stats::signal() const
{
    return signalCount ? std::optional<double>(signalSum / signalCount) : std::nullopt;
}
std::optional<double> Stats::rate() const
{
    return rateCount ? std::optional<double>(rateSum / rateCount) : std::nullopt;
}
void Stats::add(const Sample &p)
{
    ++packets;
    if (p.retryEligible) { ++retryEligible; retries += p.retry; }
    if (p.signalDbm && std::isfinite(*p.signalDbm)) { ++signalCount; signalSum += *p.signalDbm; }
    if (p.rateMbps && std::isfinite(*p.rateMbps) && *p.rateMbps > 0) { ++rateCount; rateSum += *p.rateMbps; }
}

bool Model::append(const Sample &sample)
{
    if (!sample.frame || sample.frame <= lastFrame_) return false;
    if (samples_.size() >= SampleLimit) { limited_ = true; return false; }
    samples_.append(sample);
    lastFrame_ = sample.frame;
    return true;
}
void Model::clear()
{
    samples_.clear(); lastFrame_ = 0; limited_ = false;
}
QVector<Roam> Model::roaming() const
{
    QVector<const Sample *> ordered;
    for (const auto &p : samples_)
        if (p.roamingEligible && !p.retry && p.sta && p.bssid) ordered.append(&p);
    std::sort(ordered.begin(), ordered.end(), [](const Sample *a, const Sample *b) {
        return a->timeNs == b->timeNs ? a->frame < b->frame : a->timeNs < b->timeNs;
    });
    QHash<Mac, const Sample *> last;
    QVector<Roam> result;
    for (const auto *p : ordered) {
        const auto *old = last.value(p->sta, nullptr);
        if (old && old->bssid != p->bssid)
            result.append({p->sta, old->bssid, p->bssid, old->frame, p->frame,
                           old->timeNs, p->timeNs, old->interfaceId != p->interfaceId});
        last[p->sta] = p;
    }
    return result;
}
Range Model::extent() const
{
    if (samples_.isEmpty()) return {};
    Range range{samples_.first().timeNs, samples_.first().timeNs};
    for (const auto &p : samples_) {
        range.first = std::min(range.first, p.timeNs);
        range.last = std::max(range.last, p.timeNs);
    }
    return range;
}
QString Model::groupKey(const Sample &p, Group group)
{
    return identityLabel(identity(p, group), group);
}
QMap<QString, Stats> Model::health(Group group, Range range) const
{
    QHash<quint64, Stats> totals;
    for (const auto &p : samples_) {
        if (!range.contains(p.timeNs)) continue;
        const auto key = identity(p, group);
        if (key || group == Group::Channel) totals[key].add(p);
    }
    QMap<QString, Stats> result;
    for (auto it = totals.cbegin(); it != totals.cend(); ++it)
        result.insert(identityLabel(it.key(), group), it.value());
    return result;
}
QVector<Bucket> Model::trend(Group group, const QString &key, Range range, int bins) const
{
    if (range.first > range.last) return {};
    bins = std::clamp(bins, 1, 2000);
    const long double span = static_cast<long double>(range.last) - range.first;
    QVector<Bucket> result;
    for (int i = 0; i < bins; ++i)
        result.append(Bucket{range.first + static_cast<qint64>(span * i / bins), {}});
    // Resolve a displayed label once. Never format MAC strings per packet in
    // the hot path: large captures must stay responsive during range changes.
    std::optional<quint64> selected;
    if (!key.isEmpty()) {
        QHash<quint64, bool> seen;
        for (const auto &p : samples_) {
            const auto id = identity(p, group);
            if (seen.contains(id)) continue;
            seen.insert(id, true);
            if (identityLabel(id, group) == key) { selected = id; break; }
        }
        if (!selected) return result;
    }
    for (const auto &p : samples_) {
        if (!range.contains(p.timeNs)) continue;
        const auto id = identity(p, group);
        if (selected && *selected != id) continue;
        // Unknown BSSID/STA packets are not part of that grouping's total.
        if (!id && group != Group::Channel) continue;
        const int index = span > 0 ? std::min(bins - 1, static_cast<int>(
                    (static_cast<long double>(p.timeNs) - range.first) * bins / span)) : 0;
        result[index].stats.add(p);
    }
    return result;
}
}
