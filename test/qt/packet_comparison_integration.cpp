/*
 * Real GUI packet-comparison regression; uses production application startup.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define main wireshark_application_main
#include "ui/qt/main.cpp"
#undef main

#include "ui/qt/packet_comparison_dialog.h"
#include "ui/qt/packet_list.h"
#include "ui/qt/utils/theme_manager.h"
#include "ui/qt/widgets/hex_data_source_view.h"

#include <QAction>
#include <QCheckBox>
#include <QComboBox>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QItemSelectionModel>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QScrollBar>
#include <QTimer>
#include <QTreeWidget>
#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace {

WiresharkMainWindow *window = nullptr;
PacketList *packet_list = nullptr;
capture_file *capture = nullptr;
QElapsedTimer startup_timer;
int failures = 0;
QByteArray base_bytes, ttl_bytes, vlan_bytes, truncated_bytes;

bool check(bool condition, const char *message)
{
    fprintf(stderr, "%s: %s\n", condition ? "PASS" : "FAIL", message);
    if (!condition) failures++;
    return condition;
}

void require(bool condition, const char *message)
{
    if (!check(condition, message)) throw std::runtime_error(message);
}

void settleEvents()
{
    for (int i = 0; i < 3; i++) {
        QCoreApplication::sendPostedEvents(nullptr, QEvent::MetaCall);
        QCoreApplication::processEvents(QEventLoop::AllEvents);
    }
}

template <typename Widget>
Widget *control(QObject *parent, const char *name)
{
    auto *widget = parent->findChild<Widget *>(QString::fromUtf8(name));
    require(widget != nullptr, name);
    return widget;
}

QByteArray fixtureBytes(const char *name)
{
    QFile file(qEnvironmentVariable("WS_PACKET_COMPARISON_FIXTURE_DIR") + QLatin1Char('/') + QString::fromUtf8(name));
    require(file.open(QIODevice::ReadOnly), "expected fixture bytes are readable");
    return file.readAll();
}

QTreeWidgetItem *field(QTreeWidget *tree, const QString &key)
{
    for (QTreeWidgetItemIterator item(tree); *item; ++item) {
        if ((*item)->data(0, Qt::UserRole + 2).toString() == key) return *item;
    }
    return nullptr;
}

QString treeSnapshot(PacketComparisonDialog *dialog)
{
    auto *tree = control<QTreeWidget>(dialog, "comparisonTree");
    QStringList result{tree->headerItem()->text(1), tree->headerItem()->text(2),
                       control<QLabel>(dialog, "comparisonSummary")->text()};
    for (QTreeWidgetItemIterator item(tree); *item; ++item) {
        result << (*item)->data(0, Qt::UserRole + 2).toString();
        for (int column = 0; column < 4; column++) result << (*item)->text(column);
    }
    return result.join(QChar(0x1f));
}

bool effectivelyVisible(QTreeWidgetItem *item)
{
    for (; item; item = item->parent()) if (item->isHidden()) return false;
    return true;
}

double luminance(const QColor &color)
{
    auto linear = [](double value) { return value <= 0.04045 ? value / 12.92 : std::pow((value + 0.055) / 1.055, 2.4); };
    return 0.2126 * linear(color.redF()) + 0.7152 * linear(color.greenF()) + 0.0722 * linear(color.blueF());
}

void checkNativeDarkPresentation(PacketComparisonDialog *dialog)
{
    if (qEnvironmentVariable("WS_PACKET_COMPARE_THEME") != QStringLiteral("dark") ||
        QGuiApplication::platformName() != QStringLiteral("cocoa")) return;
    settleEvents();
    auto *tree = control<QTreeWidget>(dialog, "comparisonTree");
    auto *parent = field(tree, QStringLiteral("ip"));
    require(parent != nullptr, "native dark comparison contains an unselected changed parent row");
    QColor foreground = parent->foreground(0).style() == Qt::NoBrush ?
        tree->palette().color(QPalette::Text) : parent->foreground(0).color();
    QColor background = parent->background(0).style() == Qt::NoBrush ?
        tree->palette().color(QPalette::Base) : parent->background(0).color();
    const double fg = luminance(foreground), bg = luminance(background);
    check(bg < 0.2, "native dark comparison uses a dark field background");
    check((std::max(fg, bg) + 0.05) / (std::min(fg, bg) + 0.05) >= 4.5,
          "unselected changed text remains readable against its native dark background");

    int last_row = 0;
    for (QTreeWidgetItemIterator item(tree); *item; ++item) {
        if (effectivelyVisible(*item)) last_row = std::max(last_row, tree->visualItemRect(*item).bottom());
    }
    const int start = last_row + 2 * tree->fontMetrics().height();
    const int end = tree->viewport()->height() - 6;
    require(end > start, "the comparison has an empty viewport region to inspect");
    const QPixmap pixels = tree->viewport()->grab();
    const QImage image = pixels.toImage();
    const qreal scale = pixels.devicePixelRatio();
    const int x = qRound(tree->viewport()->width() * scale / 2);
    double lowest = 1.0, highest = 0.0;
    for (int y = start; y < end; y += std::max(1, tree->fontMetrics().height() / 3)) {
        const double value = luminance(image.pixelColor(x, qRound(y * scale)));
        lowest = std::min(lowest, value); highest = std::max(highest, value);
    }
    check(highest - lowest < 0.08, "empty native dark viewport has no bright zebra stripes");
}

void checkBytes(PacketComparisonDialog *dialog, const QByteArray &left, const QByteArray &right)
{
    check(static_cast<IDataPrintable *>(control<HexDataSourceView>(dialog, "comparisonLeftBytes"))->printableData() == left,
          "left Hex view owns the exact expected captured bytes");
    check(static_cast<IDataPrintable *>(control<HexDataSourceView>(dialog, "comparisonRightBytes"))->printableData() == right,
          "right Hex view owns the exact expected captured bytes");
}

PacketComparisonDialog *create(unsigned left, unsigned right)
{
    QElapsedTimer timer;
    timer.start();
    const QString previous = window->getFilter();
    const unsigned count = capture->displayed_count;
    QString error;
    auto *dialog = PacketComparisonDialog::create(window, *window->captureFile(), left, right, error);
    if (!dialog) fprintf(stderr, "CREATE ERROR: %s\n", qPrintable(error));
    require(dialog && error.isEmpty(), "real capture-file snapshots create a comparison dialog");
    dialog->show();
    settleEvents();
    fprintf(stderr, "COMPARISON TIMING: #%u vs #%u snapshot + dialog/tree/Hex ready: %lld ms\n",
            left, right, static_cast<long long>(timer.elapsed()));
    check(window->getFilter() == previous && QString::fromUtf8(capture->dfilter) == previous &&
          capture->displayed_count == count, "creating a comparison preserves the main filter and packet list");
    return dialog;
}

void saveScreenshot(PacketComparisonDialog *dialog, const QString &name)
{
    const QString folder = qEnvironmentVariable("WS_PACKET_COMPARE_SCREENSHOT_DIR");
    if (!folder.isEmpty()) {
        settleEvents();
        check(dialog->grab().save(folder + QLatin1Char('/') + name), "real comparison screenshot is saved when requested");
    }
}

void closeDialog(PacketComparisonDialog *dialog)
{
    QPointer<PacketComparisonDialog> pointer(dialog);
    dialog->close();
    settleEvents();
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    check(pointer.isNull(), "closing the comparison releases its snapshot window");
}

void selectSingle(int number)
{
    packet_list->goToPacket(number);
    settleEvents();
    const auto frames = window->selectedFrames();
    require(frames.size() == 1 && frames.first()->num == static_cast<unsigned>(number),
            "normal packet-list navigation selects the requested frame");
}

PacketComparisonDialog *onlyDialog()
{
    const auto dialogs = window->findChildren<PacketComparisonDialog *>();
    require(dialogs.size() == 1, "the main action opens exactly one comparison window");
    return dialogs.first();
}

QList<QPushButton *> goButtons(PacketComparisonDialog *dialog)
{
    QList<QPushButton *> result;
    for (auto *button : dialog->findChildren<QPushButton *>()) {
        if (button->text() == PacketComparisonDialog::tr("Go to left packet") ||
            button->text() == PacketComparisonDialog::tr("Go to right packet")) result.append(button);
    }
    require(result.size() == 2, "both source packet navigation buttons exist");
    return result;
}

void exercise()
{
    require(capture->count == 6 && capture->displayed_count == 6, "all six UDP/VLAN/truncated fixture packets are loaded");
    base_bytes = fixtureBytes("base.bin"); ttl_bytes = fixtureBytes("ttl.bin");
    vlan_bytes = fixtureBytes("vlan.bin"); truncated_bytes = fixtureBytes("truncated.bin");
    int scans = 0;
    auto scan_connection = QObject::connect(window->captureFile(), &CaptureFile::captureEvent,
                                            window, [&](CaptureEvent event) {
        if ((event.captureContext() == CaptureEvent::Rescan || event.captureContext() == CaptureEvent::Retap) &&
            event.eventType() == CaptureEvent::Started) scans++;
    });

    auto *dialog = create(1, 2);
    auto *tree = control<QTreeWidget>(dialog, "comparisonTree");
    int visible = 0;
    for (QTreeWidgetItemIterator item(tree); *item; ++item) visible += effectivelyVisible(*item);
    check(visible == 0, "identical packet bytes in different frames have no visible semantic differences by default");
    checkBytes(dialog, base_bytes, base_bytes);
    control<QCheckBox>(dialog, "comparisonOnlyDifferences")->setChecked(false);
    for (const auto &key : {QStringLiteral("eth"), QStringLiteral("ip"), QStringLiteral("udp"), QStringLiteral("ip.ttl")}) {
        auto *item = field(tree, key);
        check(item && item->text(3) == PacketComparisonDialog::tr("Equal"),
              "typed equality keeps identical protocol/container values equal despite frame display labels");
    }
    closeDialog(dialog);

    dialog = create(1, 3);
    tree = control<QTreeWidget>(dialog, "comparisonTree");
    auto *ttl = field(tree, QStringLiteral("ip.ttl"));
    require(ttl && ttl->text(3) == PacketComparisonDialog::tr("Changed"), "a real TTL change is a typed field difference");
    const QString left_ttl = ttl->text(1), right_ttl = ttl->text(2);
    check(left_ttl != right_ttl, "the TTL difference displays both captured values");
    checkBytes(dialog, base_bytes, ttl_bytes);
    control<QCheckBox>(dialog, "comparisonDynamic")->setChecked(true);
    auto *ip_checksum = field(tree, QStringLiteral("ip.checksum"));
    check(ip_checksum && ip_checksum->text(3) == PacketComparisonDialog::tr("Ignored"), "dynamic-field rules ignore the recalculated IP checksum");
    check(field(tree, QStringLiteral("ip.ttl"))->text(3) == PacketComparisonDialog::tr("Changed"), "ignoring dynamic fields preserves the meaningful TTL change");
    control<QCheckBox>(dialog, "comparisonMetadata")->setChecked(true);
    auto *number = field(tree, QStringLiteral("frame.number"));
    check(number && number->text(3) == PacketComparisonDialog::tr("Changed"), "capture metadata can expose different frame numbers");
    control<QCheckBox>(dialog, "comparisonMetadata")->setChecked(false);
    control<QCheckBox>(dialog, "comparisonGenerated")->setChecked(true);
    control<QCheckBox>(dialog, "comparisonGenerated")->setChecked(false);
    control<QPushButton>(dialog, "comparisonSwap")->click();
    ttl = field(tree, QStringLiteral("ip.ttl"));
    check(ttl && ttl->text(1) == right_ttl && ttl->text(2) == left_ttl, "Swap exchanges field values and packet sides");
    checkBytes(dialog, ttl_bytes, base_bytes);
    control<QPushButton>(dialog, "comparisonSwap")->click();
    control<QPushButton>(dialog, "comparisonNext")->click();
    check(tree->currentItem() && tree->currentItem()->text(3) == PacketComparisonDialog::tr("Changed"), "Next difference selects an actionable changed field");
    auto *left_view = control<HexDataSourceView>(dialog, "comparisonLeftBytes");
    require(QMetaObject::invokeMethod(left_view, "byteSelected", Qt::DirectConnection, Q_ARG(int, 22)), "Hex byte-selection signal follows the production field-link path");
    check(tree->currentItem() && tree->currentItem()->data(0, Qt::UserRole + 2).toString() == QStringLiteral("ip.ttl"), "selecting the TTL byte selects the smallest matching protocol field");
    auto *source = control<QComboBox>(dialog, "comparisonSource");
    check(source->findText(QStringLiteral("Frame")) >= 0, "original Frame data is an explicit byte source");
    checkNativeDarkPresentation(dialog);
    saveScreenshot(dialog, QStringLiteral("comparison.png"));
    closeDialog(dialog);

    dialog = create(1, 4);
    checkBytes(dialog, base_bytes, vlan_bytes);
    auto *vlan = field(control<QTreeWidget>(dialog, "comparisonTree"), QStringLiteral("vlan.id"));
    check(vlan && vlan->data(0, Qt::UserRole).toInt() == -1 && vlan->data(0, Qt::UserRole + 1).toInt() >= 0,
          "VLAN-only fields remain explicitly present on the tagged side");
    closeDialog(dialog);
    dialog = create(1, 5);
    checkBytes(dialog, base_bytes, truncated_bytes);
    bool truncated_notice = false;
    bool captured_reported_counts = false;
    for (auto *label : dialog->findChildren<QLabel *>()) {
        const bool notice = label->text().contains(PacketComparisonDialog::tr(" Truncated capture: uncaptured bytes cannot be compared."));
        truncated_notice |= notice;
        captured_reported_counts |= notice && label->text().contains(QStringLiteral("50/55")) &&
                                    label->text().contains(QStringLiteral("55/55"));
    }
    check(truncated_notice, "truncated captures explain why uncaptured tail bytes cannot be compared");
    check(captured_reported_counts, "truncated Frame source reports 50 captured bytes out of the original 55");
    closeDialog(dialog);
    QString error;
    auto *invalid = PacketComparisonDialog::create(window, *window->captureFile(), 1, 99, error);
    check(!invalid && !error.isEmpty(), "a nonexistent frame produces an explicit factory error");
    check(scans == 0, "individual packet comparisons do not rescan or retap the complete capture");
    QObject::disconnect(scan_connection);

    selectSingle(1);
    const QModelIndex first = packet_list->selectionModel()->currentIndex();
    selectSingle(3);
    const QModelIndex third = packet_list->selectionModel()->currentIndex();
    packet_list->selectionModel()->select(first, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    packet_list->selectionModel()->select(third, QItemSelectionModel::Select | QItemSelectionModel::Rows);
    settleEvents();
    require(window->selectedFrames().size() == 2, "real packet-list selection contains two frames");
    auto *compare_selected = control<QAction>(window, "actionCompareSelectedPackets");
    require(compare_selected->isEnabled(), "two selected packets enable the normal comparison action");
    compare_selected->trigger(); settleEvents();
    dialog = onlyDialog();
    checkBytes(dialog, base_bytes, ttl_bytes);
    closeDialog(dialog);

    selectSingle(1);
    auto *set_baseline = control<QAction>(window, "actionSetComparisonBaseline");
    require(set_baseline->isEnabled(), "one selected packet enables Set Baseline");
    set_baseline->trigger(); settleEvents();
    auto *compare_baseline = control<QAction>(window, "actionCompareWithBaseline");
    check(!compare_baseline->isEnabled(), "a baseline packet cannot be compared with itself");
    selectSingle(3);
    require(compare_baseline->isEnabled(), "another selected packet enables Compare with Baseline");
    compare_baseline->trigger(); settleEvents();
    dialog = onlyDialog();
    checkBytes(dialog, base_bytes, ttl_bytes);
    const QString stable_tree = treeSnapshot(dialog);
    auto buttons = goButtons(dialog);
    check(buttons[0]->isEnabled() && buttons[1]->isEnabled(), "source navigation is enabled while the original capture remains open");
    buttons[0]->click(); settleEvents();
    check(capture->current_frame && capture->current_frame->num == 1, "Go to left packet uses normal main-window navigation");
    buttons[1]->click(); settleEvents();
    check(capture->current_frame && capture->current_frame->num == 3, "Go to right packet uses normal main-window navigation");
    selectSingle(4);
    window->filterPackets(QStringLiteral("frame.number >= 4")); settleEvents();
    check(treeSnapshot(dialog) == stable_tree, "changing main selection and display filter leaves the owned comparison snapshot unchanged");
    checkBytes(dialog, base_bytes, ttl_bytes);
    window->captureFile()->reload(); settleEvents();
    capture = window->captureFile()->capFile();
    require(capture && capture->count == 6, "normal capture reload completes");
    check(treeSnapshot(dialog) == stable_tree, "comparison fields survive capture reload without borrowed dissection pointers");
    checkBytes(dialog, base_bytes, ttl_bytes);
    check(!buttons[0]->isEnabled() && !buttons[1]->isEnabled(), "reloading the source disables jumps to stale frame identities");
    control<QAction>(window, "actionFileClose")->trigger(); settleEvents();
    check(!window->captureFile()->isValid(), "the normal File Close action closes the source capture");
    check(treeSnapshot(dialog) == stable_tree, "comparison fields remain available after source close");
    checkBytes(dialog, base_bytes, ttl_bytes);
    check(!buttons[0]->isEnabled() && !buttons[1]->isEnabled(), "source jumps remain disabled after close");
    check(!control<QAction>(window, "actionClearComparisonBaseline")->isEnabled(), "closing the capture clears its comparison baseline");
    check(!dialog->grab().isNull(), "the retained snapshot still paints after source buffers are released");
    closeDialog(dialog);
}

void exerciseLargeSource()
{
    require(capture->count == 2, "large-source fixture contains only two USB transfers");
    const QByteArray left = fixtureBytes("large-left.bin"), right = fixtureBytes("large-right.bin");
    auto *dialog = create(1, 2);
    checkBytes(dialog, left, right);
    require(left.size() > 1024 * 1024 && right.size() == left.size(), "both sources contain a full 1 MiB payload");
    dialog->resize(1400, 900);
    settleEvents();
    for (const char *name : {"comparisonLeftBytes", "comparisonRightBytes"}) {
        auto *view = control<HexDataSourceView>(dialog, name);
        auto visible = view->visibleByteRange();
        check(visible.first >= 0 && visible.second > 0 && visible.second < view->dataSize(),
              "large Hex source exposes a viewport-sized byte range after resize");
        require(view->verticalScrollBar()->maximum() > 0, "large Hex sources provide a scrollable viewport");
        QElapsedTimer timer; timer.start();
        view->verticalScrollBar()->setValue(view->verticalScrollBar()->maximum());
        settleEvents();
        visible = view->visibleByteRange();
        check(visible.first > 0 && visible.first < view->dataSize() &&
              visible.first + visible.second >= view->dataSize(), "large Hex viewport reaches the final captured bytes");
        check(!view->grab().isNull(), "large Hex source still paints after scrolling to its tail");
        fprintf(stderr, "COMPARISON SCROLL TIMING: %s final viewport: %lld ms\n",
                name, static_cast<long long>(timer.elapsed()));
    }
    saveScreenshot(dialog, QStringLiteral("comparison-large.png"));
    closeDialog(dialog);
}

void runChecks()
{
    try {
        const QString language = qEnvironmentVariable("WS_PACKET_COMPARE_LANGUAGE");
        if (!language.isEmpty()) {
            mainApp->loadLanguage(language);
            if (language.startsWith(QStringLiteral("zh"))) {
                check(PacketComparisonDialog::tr("Swap") != QStringLiteral("Swap"), "Chinese comparison translations are loaded");
            }
        }
        const QString theme = qEnvironmentVariable("WS_PACKET_COMPARE_THEME");
        if (theme == QStringLiteral("dark")) ThemeManager::instance()->setMode(ThemeManager::ThemeMode::Dark);
        if (theme == QStringLiteral("light")) ThemeManager::instance()->setMode(ThemeManager::ThemeMode::Light);
        if (!theme.isEmpty()) check(ThemeManager::instance()->isDarkMode() == (theme == QStringLiteral("dark")),
                                    "requested comparison QA theme is active");
        settleEvents();
        if (qEnvironmentVariableIsSet("WS_PACKET_COMPARISON_LARGE_SOURCE")) exerciseLargeSource();
        else exercise();
    }
    catch (const std::exception &error) {
        fprintf(stderr, "INTEGRATION STOP: %s\n", error.what());
        failures++;
    }
    fprintf(stderr, "PACKET COMPARISON INTEGRATION RESULT: %d failure(s)\n", failures);
    QCoreApplication::exit(failures ? 1 : 0);
}

void waitForCapture()
{
    for (QWidget *widget : QApplication::topLevelWidgets()) {
        window = qobject_cast<WiresharkMainWindow *>(widget);
        if (window) break;
    }
    capture = window ? window->captureFile()->capFile() : nullptr;
    packet_list = window ? window->findChild<PacketList *>() : nullptr;
    if (capture && capture->count && capture->edt && !capture->read_lock && packet_list) {
        settleEvents(); runChecks();
    } else if (startup_timer.elapsed() > 30000) {
        check(false, "capture and real packet list become ready within 30 seconds");
        QCoreApplication::exit(1);
    } else QTimer::singleShot(50, waitForCapture);
}

void scheduleChecks()
{
    startup_timer.start();
    QTimer::singleShot(0, waitForCapture);
}

} // namespace

Q_COREAPP_STARTUP_FUNCTION(scheduleChecks)

int main(int argc, char **argv) { return wireshark_application_main(argc, argv); }
