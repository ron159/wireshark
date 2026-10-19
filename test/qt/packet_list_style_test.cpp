/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/qt/utils/theme_styler.h"
#include "ui/qt/utils/theme_manager.h"

#include <QApplication>
#include <QCommonStyle>
#include <QHeaderView>
#include <QImage>
#include <QListView>
#include <QListWidget>
#include <QPainter>
#include <QPushButton>
#include <QStandardItemModel>
#include <QStyledItemDelegate>
#include <QStyleFactory>
#include <QStyleOptionButton>
#include <QStyleOptionHeader>
#include <QStyleOptionViewItem>
#include <QTableView>
#include <QTableWidget>
#include <QTreeView>
#include <QTreeWidget>

#include <cstdio>
#include <cstdlib>
#include <memory>

// Keep the application view class identities without pulling in capture
// engines, application models or the application singleton.
class PacketList : public QTreeView {
    Q_OBJECT
};
class PinnedColumnView : public QTreeView {
    Q_OBJECT
};
class PinnedRowView : public QTreeView {
    Q_OBJECT
};
class ProtoTree : public QTreeView {
    Q_OBJECT
};
class ExpertInfoTreeView : public QTreeView {
    Q_OBJECT
};
class DragDropTreeView : public QTreeView {
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

    void drawPrimitive(PrimitiveElement element, const QStyleOption *option,
        QPainter *painter, const QWidget *widget = nullptr) const override
    {
        // Make leaked focus outlines observable even on platforms and styles
        // that omit the native focus frame.
        if (element == PE_FrameFocusRect) {
            painter->save();
            painter->setPen(Qt::black);
            painter->setBrush(Qt::NoBrush);
            painter->drawRect(option->rect.adjusted(0, 0, -1, -1));
            painter->restore();
            return;
        }
        QCommonStyle::drawPrimitive(element, option, painter, widget);
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

// Use Qt's independent common item renderer as the pixel reference. Its proxy
// still supplies native metrics, indicators and focus frames, as in the app.
class CommonItemReference : public QProxyStyle
{
public:
    explicit CommonItemReference(QStyle *base) : QProxyStyle(base) {}

    void drawControl(ControlElement element, const QStyleOption *option,
        QPainter *painter, const QWidget *widget = nullptr) const override
    {
        if (element == CE_ItemViewItem) {
            QCommonStyle::drawControl(element, option, painter, widget);
            return;
        }
        QProxyStyle::drawControl(element, option, painter, widget);
    }

    void drawPrimitive(PrimitiveElement element, const QStyleOption *option,
        QPainter *painter, const QWidget *widget = nullptr) const override
    {
        if (element == PE_PanelItemViewRow || element == PE_PanelItemViewItem) {
            QCommonStyle::drawPrimitive(element, option, painter, widget);
            return;
        }
        QProxyStyle::drawPrimitive(element, option, painter, widget);
    }
};

static QImage render(QStyle &style, QStyleOptionViewItem option,
    const QWidget *widget, int element, qreal scale = 1.0,
    const QColor &viewport = untouched, bool alternatingRow = false)
{
    QImage image(qRound(96 * scale), qRound(28 * scale), QImage::Format_ARGB32);
    image.setDevicePixelRatio(scale);
    image.fill(viewport);
    QPainter painter(&image);
    // Item-view delegates draw over an already cleared viewport and, for
    // alternating rows, the row background painted by the view first.
    if (alternatingRow && element != 1)
        style.drawPrimitive(QStyle::PE_PanelItemViewRow, &option, &painter, widget);
    if (element == 0)
        style.drawControl(QStyle::CE_ItemViewItem, &option, &painter, widget);
    else
        style.drawPrimitive(element == 1 ? QStyle::PE_PanelItemViewRow
                                         : QStyle::PE_PanelItemViewItem,
            &option, &painter, widget);
    return image;
}

static bool uniformCell(const QImage &image, const QColor &fill, const QString &name,
    const QColor &viewport = untouched)
{
    QImage reference(image.size(), image.format());
    reference.setDevicePixelRatio(image.devicePixelRatio());
    reference.fill(viewport);
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

static QImage renderControl(QStyle &style, const QStyleOption &option,
    const QWidget *widget, QStyle::ControlElement element, qreal scale)
{
    QImage image(qRound(96 * scale), qRound(28 * scale), QImage::Format_ARGB32);
    image.setDevicePixelRatio(scale);
    image.fill(untouched);
    QPainter painter(&image);
    style.drawControl(element, &option, &painter, widget);
    return image;
}

static QImage renderIndicator(QStyle &style, const QStyleOptionViewItem &option,
    const QWidget *widget, qreal scale)
{
    QImage image(qRound(96 * scale), qRound(28 * scale), QImage::Format_ARGB32);
    image.setDevicePixelRatio(scale);
    image.fill(untouched);
    QPainter painter(&image);
    style.drawPrimitive(QStyle::PE_IndicatorItemViewItemCheck, &option, &painter, widget);
    return image;
}

static QImage renderDelegate(const QStyledItemDelegate &delegate,
    const QStyleOptionViewItem &option, const QModelIndex &index, qreal scale)
{
    QImage image(qRound(96 * scale), qRound(28 * scale), QImage::Format_ARGB32);
    image.setDevicePixelRatio(scale);
    image.fill(option.palette.color(QPalette::Base));
    QPainter painter(&image);
    delegate.paint(&painter, option, index);
    return image;
}

static QStyleOptionViewItem itemOption(const QWidget *widget, bool dark, int state,
    int background = 0)
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
    if (background != 1) option.features = QStyleOptionViewItem::Alternate;
    if (background == 0) option.backgroundBrush = QColor(dark ? "#3a5231" : "#b4e19f");
    option.palette.setColor(QPalette::Base, QColor(dark ? "#202124" : "#ffffff"));
    option.palette.setColor(QPalette::AlternateBase, QColor(dark ? "#3a5231" : "#b4e19f"));
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
    QTreeWidget treeWidget;
    QTableView table;
    QTableWidget tableWidget;
    QListView list;
    QListWidget listWidget;
    ProtoTree protocolTree;
    ExpertInfoTreeView expertInfo;
    DragDropTreeView coloringRules;
    const QList<QWidget *> packetViews{&packets, &columns, &rows};
    const QList<QWidget *> otherViews{&ordinary, &treeWidget, &table, &tableWidget,
        &list, &listWidget, &protocolTree, &expertInfo, &coloringRules};
    const QList<QWidget *> allViews = packetViews + otherViews;
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
        CommonItemReference commonReference(native ? QStyleFactory::create(key) : new InsetItemStyle(key));
        for (const QWidget *view : allViews) {
            const bool flat = key == "windows11";
            const bool packet = packetViews.contains(const_cast<QWidget *>(view));
            for (bool dark : {false, true}) {
                for (int variant = 0; variant < 144; ++variant) {
                    const int background = variant / 48;
                    const bool focus = variant % 48 >= 24;
                    auto option = itemOption(view, dark, variant % 6, background);
                    option.viewItemPosition = positions[(variant % 24) / 6];
                    if (focus) option.state |= QStyle::State_HasFocus;
                    const auto group = option.state & QStyle::State_Active ? QPalette::Active : QPalette::Inactive;
                    const QColor expected = option.state & QStyle::State_Selected
                        ? option.palette.color(group, QPalette::Highlight)
                        : option.palette.color(background == 1 ? QPalette::Base : QPalette::AlternateBase);
                    const QColor viewport = background ? option.palette.color(QPalette::Base) : untouched;
                    for (bool useOptionWidget : {false, true}) {
                        for (qreal scale : flat ? QList<qreal>{1.0, 1.25, 1.5, 2.0} : QList<qreal>{1.0})
                        for (int element = 0; element < 3; ++element) {
                            const auto image = render(style, option, useOptionWidget ? nullptr : view,
                                element, scale, viewport, background == 2);
                            const QString name = QString("%1/%2/dark=%3/variant=%4/optionWidget=%5/element=%6/scale=%7/focus=%8")
                                .arg(styleName, view->metaObject()->className()).arg(dark)
                                .arg(variant).arg(useOptionWidget).arg(element).arg(scale).arg(focus);
                            ++checks;
                            if (flat && (!focus || packet || element != 0)) {
                                failures += !uniformCell(image, expected, name, viewport);
                            } else if (flat) {
                                // QCommonStyle's focus frame must remain visible in
                                // ordinary views, including keyboard-accessible dialogs.
                                const auto expectedImage = render(commonReference, option,
                                    view, element, scale, viewport, background == 2);
                                if (image != expectedImage) {
                                    std::fprintf(stderr, "FAIL common item focus: %s\n", qPrintable(name));
                                    ++failures;
                                }
                            } else if (image != render(*reference, option,
                                useOptionWidget ? nullptr : view, element, scale, viewport, background == 2)) {
                                std::fprintf(stderr, "FAIL preserved style: %s\n", qPrintable(name));
                                ++failures;
                            }
                        }
                    }
                }
            }
        }
        // Packet views deliberately suppress focus outlines; ordinary dialogs
        // must continue showing which item has keyboard focus. The fixture
        // supplies a visible frame independently of platform focus preferences.
        if (!native && key == "windows11") {
            for (QWidget *view : otherViews) {
                auto focused = itemOption(view, false, 0);
                focused.state |= QStyle::State_HasFocus;
                const auto plain = itemOption(view, false, 0);
                ++checks;
                if (render(style, focused, view, 0) == render(style, plain, view, 0)) {
                    std::fprintf(stderr, "FAIL missing keyboard focus: %s\n", view->metaObject()->className());
                    ++failures;
                }
            }
        }

        // Native non-item controls and checkbox indicators must remain
        // unchanged, even though the item background renderer is replaced.
        QPushButton button;
        QHeaderView header(Qt::Horizontal);
        for (bool dark : {false, true})
        for (bool pressed : {false, true})
        for (qreal scale : {1.0, 1.25, 1.5, 2.0}) {
            QStyleOptionButton buttonOption;
            buttonOption.initFrom(&button);
            buttonOption.rect = cell;
            buttonOption.text = "Apply";
            buttonOption.palette = itemOption(&button, dark, 0).palette;
            buttonOption.state = QStyle::State_Enabled | (pressed ? QStyle::State_Sunken : QStyle::State_Raised);
            ++checks;
            if (renderControl(style, buttonOption, &button, QStyle::CE_PushButton, scale)
                != renderControl(*reference, buttonOption, &button, QStyle::CE_PushButton, scale)) {
                std::fprintf(stderr, "FAIL preserved button: %s\n", qPrintable(styleName));
                ++failures;
            }
            QStyleOptionHeader headerOption;
            headerOption.initFrom(&header);
            headerOption.rect = cell;
            headerOption.palette = buttonOption.palette;
            headerOption.orientation = Qt::Horizontal;
            headerOption.state = buttonOption.state | QStyle::State_Horizontal;
            ++checks;
            if (renderControl(style, headerOption, &header, QStyle::CE_HeaderSection, scale)
                != renderControl(*reference, headerOption, &header, QStyle::CE_HeaderSection, scale)) {
                std::fprintf(stderr, "FAIL preserved header: %s\n", qPrintable(styleName));
                ++failures;
            }
            auto checkOption = itemOption(&coloringRules, dark, 0);
            checkOption.rect = QRect(8, 6, 16, 16);
            checkOption.state |= pressed ? QStyle::State_On : QStyle::State_Off;
            ++checks;
            if (renderIndicator(style, checkOption, &coloringRules, scale)
                != renderIndicator(*reference, checkOption, &coloringRules, scale)) {
                std::fprintf(stderr, "FAIL preserved checkbox indicator: %s\n", qPrintable(styleName));
                ++failures;
            }
        }

        // Coloring-rule rows use a real delegate and model BackgroundRole,
        // with editable text and a checkable enabled column.
        QStandardItemModel model(1, 1);
        const auto index = model.index(0, 0);
        model.setData(index, "Rule", Qt::DisplayRole);
        model.item(0, 0)->setEditable(true);
        QStyledItemDelegate delegate;
        for (QWidget *view : otherViews)
        for (bool dark : {false, true})
        for (int state = 0; state < 6; ++state)
        for (qreal scale : {1.0, 1.25, 1.5, 2.0}) {
            auto option = itemOption(view, dark, state);
            const QColor background(dark ? "#3a5231" : "#b4e19f");
            model.setData(index, background, Qt::BackgroundRole);
            model.setData(index, Qt::Checked, Qt::CheckStateRole);
            view->setStyle(&style);
            const auto actual = renderDelegate(delegate, option, index, scale);
            view->setStyle(key == "windows11" ? static_cast<QStyle *>(&commonReference) : reference.get());
            const auto expected = renderDelegate(delegate, option, index, scale);
            ++checks;
            if (actual != expected) {
                std::fprintf(stderr, "FAIL model background/checkable rule: %s/%s/dark=%d/state=%d/scale=%g\n",
                    qPrintable(styleName), view->metaObject()->className(), dark, state, scale);
                ++failures;
            }
            view->setStyle(&style);
            model.setData(index, Qt::Unchecked, Qt::CheckStateRole);
            const auto unchecked = renderDelegate(delegate, option, index, scale);
            // The inset-only fixture intentionally omits text and indicators.
            // Check visibility with the replacement renderer and real styles.
            if (native || key == "windows11") {
                ++checks;
                if (actual == unchecked) {
                    std::fprintf(stderr, "FAIL invisible rule checkbox: %s/%s/dark=%d/state=%d/scale=%g\n",
                        qPrintable(styleName), view->metaObject()->className(), dark, state, scale);
                    ++failures;
                }
            }
            view->setStyle(nullptr);
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
    std::printf("Item-view style: %d checks, %d failures\n", checks, failures);
    return failures ? 1 : 0;
}

#include "packet_list_style_test.moc"
