/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "wireless_analysis.h"
#include <algorithm>
#include <cmath>

namespace WirelessAnalysis {
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
    QMap<Mac, const Sample *> last;
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
    if (group == Group::AccessPoint) return p.bssid ? macString(p.bssid) : QString();
    if (group == Group::Station) return p.sta ? macString(p.sta) : QString();
    if (p.frequency) return QString::number(p.frequency) + QStringLiteral(" MHz");
    if (p.channel) return QStringLiteral("Channel %1 (band unknown)").arg(p.channel);
    return QStringLiteral("Unknown");
}
QMap<QString, Stats> Model::health(Group group, Range range) const
{
    QMap<QString, Stats> result;
    for (const auto &p : samples_) {
        if (!range.contains(p.timeNs)) continue;
        const auto key = groupKey(p, group);
        if (!key.isEmpty()) result[key].add(p);
    }
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
    for (const auto &p : samples_) {
        if (!range.contains(p.timeNs) || (!key.isEmpty() && groupKey(p, group) != key)) continue;
        // Unknown BSSID/STA packets are not part of that grouping's total.
        if (groupKey(p, group).isEmpty()) continue;
        const int index = span > 0 ? std::min(bins - 1, static_cast<int>(
                    (static_cast<long double>(p.timeNs) - range.first) * bins / span)) : 0;
        result[index].stats.add(p);
    }
    return result;
}
}
