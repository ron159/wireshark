/** @file
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include <QDialog>
#include <QSet>
#include "utils/packet_comparison.h"

class CaptureFile;
class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QTreeWidget;
class QTreeWidgetItem;
class HexDataSourceView;

class PacketComparisonDialog : public QDialog
{
    Q_OBJECT
public:
    static PacketComparisonDialog *create(QWidget *parent, CaptureFile &capture,
                                         unsigned left, unsigned right, QString &error);
    void invalidateSource();
signals:
    void goToPacket(unsigned number);
private:
    PacketComparisonDialog(QWidget *parent, PacketComparison::Packet left,
                           PacketComparison::Packet right, QVector<PacketComparison::Row> rows,
                           const QString &filename);
    void rebuildTree();
    void rebuildBytes();
    void selectField(QTreeWidgetItem *item);
    void navigate(int direction);
    void swapPackets();
    void copyResult();
    QString stateText(PacketComparison::State state) const;
    PacketComparison::Packet left_, right_;
    QVector<PacketComparison::Row> rows_;
    QTreeWidget *tree_;
    QWidget *bytes_container_;
    HexDataSourceView *left_bytes_ = nullptr, *right_bytes_ = nullptr;
    QCheckBox *only_differences_, *generated_, *all_fields_, *dynamic_;
    QLineEdit *search_;
    QComboBox *source_;
    QLabel *summary_, *source_status_, *byte_status_;
    QPushButton *go_left_, *go_right_;
    QSet<QString> ignored_;
    QVector<QTreeWidgetItem *> differences_;
};
