/*
 * Wireshark
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ui/qt/utils/github_release.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <cstdio>

using GitHubRelease::Platform;

static QJsonObject release(const QString &version, bool prerelease = false)
{
    return {
        {"tag_name", "v" + version},
        {"draft", false},
        {"prerelease", prerelease},
        {"assets", QJsonArray{}},
    };
}

int main()
{
    using namespace GitHubRelease;
    auto stable = release("5.1.10");
    QJsonArray assets;
    const auto download = QStringLiteral("https://github.com/ron159/wireshark/releases/download/v5.1.10/");
    const auto digest = QStringLiteral("sha256:") + QString(64, QLatin1Char('a'));
    for (const auto &name : {"Wireshark-5.1.10-x64.exe", "Wireshark-macos-arm64.zip",
                             "Wireshark-5.1.10-linux-x86_64.tar.gz"}) {
        assets.append(QJsonObject{{"name", name}, {"state", "uploaded"}, {"size", 1024},
                                 {"digest", digest}, {"browser_download_url", download + name}});
    }
    stable["assets"] = assets;
    auto makeJson = [](const QJsonObject &obj) { return QJsonDocument(obj).toJson(); };

    for (auto platform : {Platform::WindowsX64, Platform::MacOSArm64, Platform::UbuntuAmd64}) {
        const auto result = parse(makeJson(stable), false, platform);
        if (result.version != "5.1.10" || !isReleasePage(result.page) || result.size != 1024
            || result.sha256 != QByteArray(32, char(0xaa)) || !isDownloadHost(result.download)) {
            std::fprintf(stderr, "Valid platform asset not selected\n");
            return 1;
        }
    }

    auto draft = release("9.0.0");
    draft["draft"] = true;
    const auto candidates = QJsonDocument(QJsonArray{draft, release("5.1.9"), stable, release("5.1.11", true)}).toJson();
    if (parse(candidates, true, Platform::WindowsX64).version != "5.1.11"
        || !parse(makeJson(release("5.1.11", true)), false, Platform::WindowsX64).version.isEmpty()
        || !parse("broken json", false, Platform::WindowsX64).version.isEmpty()) {
        std::fprintf(stderr, "Invalid release filtering or version ordering\n");
        return 1;
    }

    auto asset = assets.first().toObject();
    asset["browser_download_url"] = QStringLiteral("https://other.example/") + asset["name"].toString();
    stable["assets"] = QJsonArray{asset};
    if (!parse(makeJson(stable), false, Platform::WindowsX64).download.isEmpty()) {
        return 1;
    }
    asset["browser_download_url"] = download + asset["name"].toString();
    asset["digest"] = "sha256:abc";
    stable["assets"] = QJsonArray{asset};
    if (!parse(makeJson(stable), false, Platform::WindowsX64).download.isEmpty()) {
        return 1;
    }

    if (isDownloadHost(QUrl("http://release-assets.githubusercontent.com/a"))
        || isDownloadHost(QUrl("https://release-assets.githubusercontent.com.example.com/a"))
        || isDownloadHost(QUrl("https://github.com:8443"))
        || isReleasePage(QUrl("https://github.com/different/wireshark/releases/tag/v5.1.7"))
        || !isDownloadHost(QUrl("https://release-assets.githubusercontent.com/a?token=test"))) {
        return 1;
    }
    return 0;
}
