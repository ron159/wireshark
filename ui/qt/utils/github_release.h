/* github_release.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QByteArray>
#include <QString>
#include <QUrl>

namespace GitHubRelease {

enum class Platform { WindowsX64, MacOSArm64, UbuntuAmd64 };

struct Release {
    QString version;
    QUrl page;
    QUrl download;
    QByteArray sha256;
    qint64 size = 0;
};

QUrl apiUrl(bool includePrereleases);
bool isReleasePage(const QUrl &url);
bool isDownloadHost(const QUrl &url);
Release parse(const QByteArray &json, bool includePrereleases, Platform platform);

}
