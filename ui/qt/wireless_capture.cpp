/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "config.h"
#include "wireless_capture.h"
#include <file.h>
#include <epan/epan_dissect.h>
#include <epan/frame_data_sequence.h>
#include <QElapsedTimer>
#include <cmath>
#include <limits>

using namespace WirelessAnalysis;
namespace {
// Prime just these fields in our own dissection tree. Presence checks also work
// for encrypted frames; decrypting application payload is not required.
const char *fields[] = {
    "wlan.fc.type_subtype", "wlan.fc.tods", "wlan.fc.fromds", "wlan.fc.retry",
    "wlan.bssid", "wlan.ta", "wlan.ra", "wlan_radio.signal_dbm",
    "wlan_radio.data_rate", "wlan_radio.frequency", "wlan_radio.channel",
    "wlan.fcs.status", "radiotap.flags.badfcs", "eapol", "_ws.malformed",
    "frame.interface_id"
};
struct Reader {
    epan_dissect_t edt;
    wtap_rec rec;
    QVector<int> ids;
    explicit Reader(capture_file *cf) {
        wtap_rec_init(&rec, DEFAULT_INIT_BUFFER_SIZE_2048);
        epan_dissect_init(&edt, cf->epan, true, false);
        for (const char *name : fields) ids.append(proto_registrar_get_id_byname(name));
    }
    ~Reader() { epan_dissect_cleanup(&edt); wtap_rec_cleanup(&rec); }
    field_info *field(int index) const {
        auto *array = ids[index] < 0 ? nullptr : proto_get_finfo_ptr_array(edt.tree, ids[index]);
        return array && array->len ? static_cast<field_info *>(array->pdata[0]) : nullptr;
    }
    quint64 number(int index) const {
        auto *f = field(index);
        if (!f) return 0;
        return f->hfinfo->type == FT_BOOLEAN ? fvalue_get_uinteger64(f->value) : fvalue_get_uinteger(f->value);
    }
    Mac mac(int index) const {
        auto *f = field(index);
        if (!f || fvalue_get_bytes_size(f->value) != 6) return 0;
        const auto *bytes = static_cast<const unsigned char *>(fvalue_get_bytes_data(f->value));
        if (bytes[0] & 1) return 0; // Group addresses never identify a STA/AP.
        Mac value = 0;
        for (int i = 0; i < 6; ++i) value = (value << 8) | bytes[i];
        return value;
    }
};
}

WirelessCapture::WirelessCapture(CaptureFile &capture, QObject *parent) : QObject(parent), capture_(capture)
{
    connect(&timer_, &QTimer::timeout, this, &WirelessCapture::scan);
    connect(&capture_, &CaptureFile::captureEvent, this, [this](CaptureEvent e) {
        if ((e.captureContext() == CaptureEvent::File && e.eventType() == CaptureEvent::Closing)
                || (e.captureContext() == CaptureEvent::Reload && e.eventType() == CaptureEvent::Started))
            invalidate();
        else if (valid_ && e.captureContext() == CaptureEvent::Rescan && e.eventType() == CaptureEvent::Finished)
            refresh();
    });
    timer_.start(0);
}
quint32 WirelessCapture::total() const
{
    const auto *cf = valid_ ? capture_.capFile() : nullptr;
    return cf ? cf->count : scanned();
}
void WirelessCapture::invalidate()
{
    valid_ = false;
    timer_.stop();
    emit updated();
}
void WirelessCapture::refresh()
{
    if (!valid_) return;
    model_.clear(); nextFrame_ = 1; error_.clear(); haveOrigin_ = false;
    timer_.start(0);
    emit updated();
}
void WirelessCapture::scan()
{
    auto *cf = valid_ ? capture_.capFile() : nullptr;
    if (!cf) { invalidate(); return; }
    if (cf->read_lock || cf->state == FILE_READ_PENDING) { timer_.start(100); return; }
    if (nextFrame_ > cf->count) { timer_.start(500); return; }
    Reader reader(cf);
    QElapsedTimer budget; budget.start();
    while (nextFrame_ <= cf->count && budget.elapsed() < 15) {
        auto *fd = frame_data_sequence_find(cf->provider.frames, nextFrame_++);
        if (!fd || !fd->has_ts) continue;
        if (!haveOrigin_) { origin_ = fd->abs_ts; haveOrigin_ = true; }
        if (fd->ignored) continue;
        if (!cf_read_record_no_alert(cf, fd, &reader.rec)) {
            error_ = tr("Could not read packet %1. Results are incomplete.").arg(fd->num);
            timer_.stop(); emit updated(); return;
        }
        for (int id : reader.ids) if (id >= 0) epan_dissect_prime_with_hfid(&reader.edt, id);
        epan_dissect_run(&reader.edt, cf->cd_t, &reader.rec, fd, nullptr);
        if (reader.field(0)) {
            Sample p;
            p.frame = fd->num;
            nstime_t delta;
            nstime_delta(&delta, &fd->abs_ts, &origin_);
            constexpr qint64 maxSeconds = std::numeric_limits<qint64>::max() / 1000000000 - 1;
            if (delta.secs > maxSeconds || delta.secs < -maxSeconds) {
                epan_dissect_reset(&reader.edt); continue;
            }
            p.timeNs = static_cast<qint64>(delta.secs) * 1000000000 + delta.nsecs;
            p.bssid = reader.mac(4);
            const Mac ta = reader.mac(5), ra = reader.mac(6);
            const auto subtype = reader.number(0);
            const auto type = subtype >> 4;
            const bool toDS = reader.number(1), fromDS = reader.number(2);
            if (type == 2 && toDS != fromDS)
                p.sta = toDS ? ta : ra;
            else if (type == 0 && p.bssid)
                p.sta = ta == p.bssid ? ra : (ra == p.bssid ? ta : 0);
            if (p.sta == p.bssid) p.sta = 0;
            p.retry = reader.number(3);
            p.retryEligible = type == 0 || type == 2;
            p.interfaceId = static_cast<quint32>(reader.number(15));
            p.frequency = static_cast<int>(reader.number(9));
            p.channel = static_cast<int>(reader.number(10));
            if (auto *f = reader.field(7)) p.signalDbm = fvalue_get_sinteger(f->value);
            if (auto *f = reader.field(8)) p.rateMbps = fvalue_get_floating(f->value);
            const bool badFcs = reader.number(12) || (reader.field(11) && reader.number(11) == PROTO_CHECKSUM_E_BAD);
            p.roamingEligible = type == 2 && !(subtype & 4) && toDS != fromDS
                    && ta && ra && p.sta && p.bssid && !badFcs && !reader.field(13) && !reader.field(14);
            model_.append(p);
        }
        epan_dissect_reset(&reader.edt);
        if (model_.limited()) { timer_.stop(); emit updated(); return; }
    }
    timer_.start(nextFrame_ > cf->count ? 500 : 0);
    emit updated();
}
