/* Translate display text from the C preference APIs without changing stored values.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/utils/qt_ui_utils.h>
#include <QCoreApplication>
#include <QRegularExpression>

QString prefs_ui_translation(const char *text)
{
    if (!text) return QString();

    const QString source = QString::fromUtf8(text);
    const QString translated = QCoreApplication::translate("Preferences", text);
    if (translated != source) return translated;

    // epan/packet.c generates preference titles from protocol names and the
    // dissector table's display name. Translate the suffix, never the protocol.
    static const char * const suffixes[] = {
        QT_TRANSLATE_NOOP("Preferences", "TCP port(s)"),
        QT_TRANSLATE_NOOP("Preferences", "UDP port(s)"),
        QT_TRANSLATE_NOOP("Preferences", "SCTP port(s)"),
        QT_TRANSLATE_NOOP("Preferences", "TLS Port(s)"),
        QT_TRANSLATE_NOOP("Preferences", "DTLS Port(s)"),
        QT_TRANSLATE_NOOP("Preferences", "RTP payload type(s)"),
        QT_TRANSLATE_NOOP("Preferences", "SCTP payload protocol identifier(s)"),
        QT_TRANSLATE_NOOP("Preferences", "IP protocol(s)"),
        QT_TRANSLATE_NOOP("Preferences", "SCCP SSN(s)"),
        QT_TRANSLATE_NOOP("Preferences", "Ethertype(s)"),
        QT_TRANSLATE_NOOP("Preferences", "USB product(s)"),
        QT_TRANSLATE_NOOP("Preferences", "ip.access Protocol(s)"),
    };
    for (const char *suffix : suffixes) {
        const QString ending = QStringLiteral(" ") + QString::fromUtf8(suffix);
        if (source.endsWith(ending)) {
            return source.left(source.size() - ending.size()) + QStringLiteral(" ")
                + QCoreApplication::translate("Preferences", suffix);
        }
    }

    // Some C registrations append defaults to an otherwise translatable title.
    static const QRegularExpression default_suffix(QStringLiteral("^(.*) \\(default: (.*)\\)$"));
    const auto match = default_suffix.match(source);
    if (match.hasMatch()) {
        return QCoreApplication::translate("Preferences", "%1 (default: %2)")
            .arg(prefs_ui_translation(match.captured(1).toUtf8().constData()), match.captured(2));
    }
    static const QRegularExpression numbered_label(QStringLiteral(
        "^(?:Context (\\d+)|Category (\\d+)|Logical Channel (\\d+) Content|"
        "(\\d+)\\. key|depth (\\d+)| Interpret (edition_[\\d_]+) as )$"));
    static const char * const formats[] = {
        QT_TRANSLATE_NOOP("Preferences", "Context %1"),
        QT_TRANSLATE_NOOP("Preferences", "Category %1"),
        QT_TRANSLATE_NOOP("Preferences", "Logical Channel %1 Content"),
        QT_TRANSLATE_NOOP("Preferences", "%1. key"),
        QT_TRANSLATE_NOOP("Preferences", "depth %1"),
        QT_TRANSLATE_NOOP("Preferences", " Interpret %1 as "),
    };
    const auto numbered = numbered_label.match(source);
    if (numbered.hasMatch()) {
        for (int index = 0; index < 6; index++) {
            if (!numbered.captured(index + 1).isEmpty()) {
                return QCoreApplication::translate("Preferences", formats[index])
                    .arg(numbered.captured(index + 1));
            }
        }
    }
    return source;
}
