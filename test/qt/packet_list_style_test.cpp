/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/qt/utils/theme_styler.h"
#include "ui/qt/utils/theme_manager.h"

#include <QApplication>
#include <QCommonStyle>
#include <QImage>
#include <QPainter>
#include <QStyleFactory>
#include <QStyleOptionViewItem>
#include <QTreeView>

#include <cstdio>
#include <cstdlib>
#include <memory>

// Keep the same QObject class identities as the three packet-list views,
// without pulling in capture engines, models or the application singleton.
class PacketList : public QTreeView {
    Q_OBJECT
};
class PinnedColumnView : public QTreeView {
    Q_OBJECT
};
class PinnedRowView : public QTreeView {
    Q_OBJECT
};

// ColorMath's translucent-button helper links these methods, but item-view
// rendering must not consult the global theme manager.
ThemeManager *ThemeManager::instance()
{
    qFatal("Unexpected ThemeManager access");
    std::abort();
}
bool ThemeManager::isDarkMode() const
{
    qFatal("Unexpected ThemeManager access");
    std::abort();
}

static const QColor untouched(255, 0, 255);
static const QRect cell(8, 6, 72, 16);

// Model the affected geometry of Qt 6.8.3 Windows 11 CE_ItemViewItem on
// every test platform (qwindows11style.cpp:1555-1608): half-pixel column
// borders, inset two-pixel backgrounds, and rounded row ends. Keep the
// primitives inherited, as Windows 11 does, rather than simulating the fix.
class InsetItemStyle : public QCommonStyle
{
public:
    explicit InsetItemStyle(const QString &name) { setObjectName(name); }

    void drawControl(ControlElement element, const QStyleOption *option,
        QPainter *painter, const QWidget *widget = nullptr) const override
    {
        if (element == CE_ItemViewItem) {
            drawInset(option, painter);
            return;
        }
        QCommonStyle::drawControl(element, option, painter, widget);
    }

private:
    static void drawInset(const QStyleOption *option, QPainter *painter)
    {
        const auto *item = qstyleoption_cast<const QStyleOptionViewItem *>(option);
        if (!item) return;
        const bool first = item->viewItemPosition == QStyleOptionViewItem::Beginning;
        const bool last = item->viewItemPosition == QStyleOptionViewItem::End;
        const bool only = item->viewItemPosition == QStyleOptionViewItem::OnlyOne
            || item->viewItemPosition == QStyleOptionViewItem::Invalid;
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing);
        painter->setPen(QColor(0, 0, 0, 15));
        if (!last)
            painter->drawLine(QPointF(item->rect.topRight()) + QPointF(0.5, 0),
                QPointF(item->rect.bottomRight()) + QPointF(0.5, 0));
        if (!first)
            painter->drawLine(QPointF(item->rect.topLeft()) - QPointF(0.5, 0),
                QPointF(item->rect.bottomLeft()) - QPointF(0.5, 0));
        painter->setPen(Qt::NoPen);
        painter->setBrush(item->state & State_Selected && !(item->state & State_MouseOver)
            ? QBrush(QColor(0, 0, 0, 9)) : item->backgroundBrush);
        const QRect inset = item->rect.marginsRemoved(QMargins(first || only ? 2 : 0,
            2, last || only ? 2 : 0, 2));
        if (first || last || only)
            painter->drawRoundedRect(inset, 4, 4);
        else
            painter->drawRect(inset);
        painter->restore();
    }
};

static QImage render(QStyle &style, QStyleOptionViewItem option,
    const QWidget *widget, int element, qreal scale = 1.0)
{
    QImage image(qRound(96 * scale), qRound(28 * scale), QImage::Format_ARGB32);
    image.setDevicePixelRatio(scale);
    image.fill(untouched);
    QPainter painter(&image);
    if (element == 0)
        style.drawControl(QStyle::CE_ItemViewItem, &option, &painter, widget);
    else
        style.drawPrimitive(element == 1 ? QStyle::PE_PanelItemViewRow
                                         : QStyle::PE_PanelItemViewItem,
            &option, &painter, widget);
    return image;
}

static bool uniformCell(const QImage &image, const QColor &fill, const QString &name)
{
    QImage reference(image.size(), image.format());
    reference.setDevicePixelRatio(image.devicePixelRatio());
    reference.fill(untouched);
    QPainter painter(&reference);
    painter.fillRect(cell, fill);
    painter.end();
    for (int y = 0; y < image.height(); ++y) {
        for (int x = 0; x < image.width(); ++x) {
            const QColor expected = reference.pixelColor(x, y);
            if (image.pixelColor(x, y) != expected) {
                std::fprintf(stderr, "FAIL %s at (%d,%d): expected %s, got %s\n",
                    qPrintable(name), x, y, qPrintable(expected.name()),
                    qPrintable(image.pixelColor(x, y).name()));
                return false;
            }
        }
    }
    return true;
}

static QStyleOptionViewItem itemOption(const QWidget *widget, bool dark, int state)
{
    QStyleOptionViewItem option;
    option.rect = cell;
    option.widget = widget;
    option.state = QStyle::State_Enabled | QStyle::State_Active;
    if (state > 0 && state < 4) option.state |= QStyle::State_Selected;
    if (state == 2 || state == 5) option.state &= ~QStyle::State_Active;
    if (state == 3 || state == 4) option.state |= QStyle::State_MouseOver;
    option.showDecorationSelected = true;
    option.viewItemPosition = QStyleOptionViewItem::Middle;
    option.features = QStyleOptionViewItem::Alternate;
    option.backgroundBrush = QColor(dark ? "#3a5231" : "#b4e19f");
    option.palette.setColor(QPalette::Base, QColor(dark ? "#202124" : "#ffffff"));
    option.palette.setColor(QPalette::AlternateBase, option.backgroundBrush.color());
    option.palette.setColor(QPalette::Active, QPalette::Highlight, QColor(dark ? "#244a77" : "#8db5ed"));
    option.palette.setColor(QPalette::Inactive, QPalette::Highlight, QColor(dark ? "#544767" : "#c8b8de"));
    return option;
}

int main(int argc, char **argv)
{
    if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM"))
        qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);
    PacketList packets;
    PinnedColumnView columns;
    PinnedRowView rows;
    QTreeView ordinary;
    int checks = 0, failures = 0;
    const QStyleOptionViewItem::ViewItemPosition positions[] = {
        QStyleOptionViewItem::Beginning, QStyleOptionViewItem::Middle,
        QStyleOptionViewItem::End, QStyleOptionViewItem::OnlyOne};

    // Each style is scoped because ThemeStyler records the process-wide base
    // style name, just as the application does when it installs its style.
    for (const QString &styleName : {QString("windows11"), QString("fusion"),
             QString("native-fusion"), QString("native-windows11")}) {
        const bool native = styleName.startsWith("native-");
        const QString key = native ? styleName.mid(7) : styleName;
        QStyle *base = native ? QStyleFactory::create(key) : new InsetItemStyle(key);
        if (!base) {
            std::printf("Native %s style: unavailable\n", qPrintable(key));
            if (key != "windows11" || qEnvironmentVariableIntValue("WS_REQUIRE_NATIVE_WINDOWS11_STYLE")) ++failures;
            continue;
        }
        if (styleName == "native-windows11") std::puts("Native windows11 style: available");
        ThemeStyler style(base);
        std::unique_ptr<QStyle> reference(native ? QStyleFactory::create(key) : new InsetItemStyle(key));
        for (const QWidget *view : QList<const QWidget *>{&packets, &columns, &rows, &ordinary}) {
            const bool flat = key == "windows11" && view != &ordinary;
            for (bool dark : {false, true}) {
                for (int variant = 0; variant < 24; ++variant) {
                    auto option = itemOption(view, dark, variant % 6);
                    option.viewItemPosition = positions[variant / 6];
                    const auto group = option.state & QStyle::State_Active ? QPalette::Active : QPalette::Inactive;
                    const QColor expected = option.state & QStyle::State_Selected
                        ? option.palette.color(group, QPalette::Highlight) : option.backgroundBrush.color();
                    for (bool useOptionWidget : {false, true}) {
                        for (qreal scale : flat ? QList<qreal>{1.0, 1.25, 1.5, 2.0} : QList<qreal>{1.0})
                        for (int element = 0; element < 3; ++element) {
                            const auto image = render(style, option, useOptionWidget ? nullptr : view, element, scale);
                            const QString name = QString("%1/%2/dark=%3/variant=%4/optionWidget=%5/element=%6/scale=%7")
                                .arg(styleName, view->metaObject()->className()).arg(dark)
                                .arg(variant).arg(useOptionWidget).arg(element).arg(scale);
                            ++checks;
                            if (flat) {
                                failures += !uniformCell(image, expected, name);
                            } else if (image != render(*reference, option,
                                useOptionWidget ? nullptr : view, element)) {
                                std::fprintf(stderr, "FAIL preserved style: %s\n", qPrintable(name));
                                ++failures;
                            }
                        }
                    }
                }
            }
        }
    }
    // Match PacketList::colorsChanged(), including the outer QStyleSheetStyle
    // that draws active/inactive selections and delegates unselected cells.
    for (bool native : {false, true}) {
        QStyle *base = native ? QStyleFactory::create("windows11") : new InsetItemStyle("windows11");
        if (!base) continue;
        ThemeStyler style(base);
        for (QWidget *view : QList<QWidget *>{&packets, &columns, &rows}) {
            view->setStyle(&style);
            view->setStyleSheet("QTreeView { outline: 0; }"
                "QTreeView::item:selected:active { color: #ffffff; background-color: #1456ab; }"
                "QTreeView::item:selected:!active { color: #ffffff; background-color: #695378; }");
            view->ensurePolished();
            for (int variant = 0; variant < 8; ++variant)
            for (qreal scale : {1.0, 1.25, 1.5, 2.0}) {
                const int state = variant % 4;
                auto option = itemOption(view, false, state);
                if (variant >= 4) option.state |= QStyle::State_HasFocus;
                const auto image = render(*view->style(), option, view, 0, scale);
                const QColor expected = state ? QColor(state == 2 ? "#695378" : "#1456ab")
                                              : option.backgroundBrush.color();
                ++checks;
                failures += !uniformCell(image, expected,
                    QString("stylesheet/native=%1/%2/state=%3/focus=%4/scale=%5")
                        .arg(native).arg(view->metaObject()->className()).arg(state).arg(variant >= 4).arg(scale));
            }
            view->setStyleSheet(QString());
            view->setStyle(nullptr);
        }
    }
    std::printf("Packet-list style: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}

#include "packet_list_style_test.moc"
