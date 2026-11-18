/* github_release.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "github_release.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QVersionNumber>

namespace GitHubRelease {

static const QString repoPath = QStringLiteral("/ron159/wireshark/releases");
static const QRegularExpression versionTag(QStringLiteral(R"(\Av([0-9]+\.[0-9]+\.[0-9]+)\z)"));

static bool isHttps(const QUrl &url)
{
    return url.isValid() && url.scheme() == QStringLiteral("https")
        && url.userInfo().isEmpty() && url.port(443) == 443;
}

QUrl apiUrl(bool includePrereleases)
{
    return QUrl(QStringLiteral("https://api.github.com/repos") + repoPath
        + (includePrereleases ? QStringLiteral("?per_page=20") : QStringLiteral("/latest")));
}

bool isReleasePage(const QUrl &url)
{
    const auto pathPrefix = repoPath + QStringLiteral("/tag/");
    return isHttps(url) && url.host() == QStringLiteral("github.com")
        && !url.hasQuery() && !url.hasFragment() && url.path().startsWith(pathPrefix)
        && versionTag.match(url.path().mid(pathPrefix.size())).hasMatch();
}

bool isDownloadHost(const QUrl &url)
{
    return isHttps(url) && (url.host() == QStringLiteral("github.com")
        || url.host() == QStringLiteral("release-assets.githubusercontent.com")
        || url.host() == QStringLiteral("objects.githubusercontent.com"));
}

static QString assetName(Platform platform, const QString &version)
{
    switch (platform) {
    case Platform::WindowsX64:
        return QStringLiteral("Wireshark-%1-x64.exe").arg(version);
    case Platform::MacOSArm64:
        return QStringLiteral("Wireshark-macos-arm64.zip");
    case Platform::UbuntuAmd64:
        return QStringLiteral("Wireshark-%1-linux-x86_64.tar.gz").arg(version);
    }
    return {};
}

Release parse(const QByteArray &json, bool includePrereleases, Platform platform)
{
    const QJsonDocument document = QJsonDocument::fromJson(json);
    const QJsonArray releases = includePrereleases ? document.array() : QJsonArray{document.object()};
    QVersionNumber newestVersion;
    QJsonObject newest;
    QString tag;
    for (const auto &value : releases) {
        const auto release = value.toObject();
        if (release.value(QStringLiteral("draft")).toBool(true)
            || (!includePrereleases && release.value(QStringLiteral("prerelease")).toBool(true))) {
            continue;
        }

        const auto candidateTag = release.value(QStringLiteral("tag_name")).toString();
        const auto match = versionTag.match(candidateTag);
        if (!match.hasMatch()) {
            continue;
        }
        const auto version = QVersionNumber::fromString(match.captured(1));
        if (version.segmentCount() == 3 && version > newestVersion) {
            newest = release;
            newestVersion = version;
            tag = candidateTag;
        }
    }
    if (newestVersion.isNull()) {
        return {};
    }

    const QString version = newestVersion.toString();
    const QString base = QStringLiteral("https://github.com") + repoPath;
    Release result{version, QUrl(base + QStringLiteral("/tag/") + tag), {}, {}, 0};
    const QString filename = assetName(platform, version);
    const QUrl downloadUrl(base + QStringLiteral("/download/") + tag + QLatin1Char('/') + filename);
    const auto assets = newest.value(QStringLiteral("assets")).toArray();
    static const QRegularExpression sha256(QStringLiteral(R"(\Asha256:([a-fA-F0-9]{64})\z)"));
    for (const auto &value : assets) {
        const auto asset = value.toObject();
        if (asset.value(QStringLiteral("name")).toString() != filename
            || asset.value(QStringLiteral("state")).toString() != QStringLiteral("uploaded")
            || QUrl(asset.value(QStringLiteral("browser_download_url")).toString(), QUrl::StrictMode) != downloadUrl) {
            continue;
        }

        const auto digest = sha256.match(asset.value(QStringLiteral("digest")).toString());
        const double size = asset.value(QStringLiteral("size")).toDouble();
        if (digest.hasMatch() && size > 0 && size <= (1 << 30) && size == static_cast<qint64>(size)) {
            result.download = downloadUrl;
            result.sha256 = QByteArray::fromHex(digest.captured(1).toLatin1());
            result.size = static_cast<qint64>(size);
            break;
        }
    }
    return result;
}

}
