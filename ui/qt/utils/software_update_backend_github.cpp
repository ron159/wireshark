/* software_update_backend_github.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "software_update_backend_github.h"
#include "software_update_backend.h"
#include "software_update.h"
#include "github_release.h"

#include "app/application_flavor.h"
#include "epan/prefs.h"
#ifdef Q_OS_WIN
#include "wsutil/file_util.h"
#endif

#include <QApplication>
#include <QCryptographicHash>
#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QLockFile>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QOperatingSystemVersion>
#include <QProcess>
#include <QProgressDialog>
#include <QPushButton>
#include <QSettings>
#include <QSysInfo>
#include <QTemporaryDir>

#include <cstdio>
#include <functional>
#include <memory>
#include <optional>

#ifdef Q_OS_MACOS
#include <fcntl.h>
#endif

namespace {

using GitHubRelease::Platform;

std::optional<Platform> currentPlatform()
{
#if defined(Q_OS_WIN) && (defined(_M_X64) || defined(__x86_64__))
    return Platform::WindowsX64;
#elif defined(Q_OS_MACOS) && defined(__aarch64__)
    if (QOperatingSystemVersion::current().majorVersion() >= 15) {
        return Platform::MacOSArm64;
    }
#elif defined(Q_OS_LINUX) && defined(__x86_64__)
    if (QSysInfo::productType() == QStringLiteral("ubuntu")
        && QSysInfo::productVersion() == QStringLiteral("24.04")
        && QCoreApplication::applicationFilePath() == QStringLiteral("/usr/bin/wireshark")) {
        return Platform::UbuntuAmd64;
    }
#endif
    return std::nullopt;
}

QNetworkRequest requestFor(const QUrl &url)
{
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::UserAgentHeader,
        QStringLiteral("Wireshark/%1").arg(QString::fromLatin1(application_version())));
    request.setTransferTimeout(30000);
    return request;
}

class GitHubUpdateBackend final : public QObject, public SoftwareUpdateBackend
{
    Q_OBJECT

public:
    explicit GitHubUpdateBackend(Platform platform) : platform_(platform) {}

    QString info() const override { return QStringLiteral("GitHub Releases"); }
    bool supportsAppcast() const override { return false; }
    void init(const QUrl &, bool) override { initialized_ = true; }
    void cleanup() override;
    bool checkForUpdates() override;
    void performUIUpdate() override;

private:
    void check(bool manual);
    void finishCheck(const QString &error, const GitHubRelease::Release &release);
    void download(const GitHubRelease::Release &release);
    void readDownload();
    void finishDownload();
    void install();
    bool prepareShutdown();
    void runTool(const QString &program, const QStringList &arguments,
                 const std::function<void(bool, QString)> &done);
    void complete(const QString &error = {});
    void showPackage(const QString &explanation);

    const Platform platform_;
    QNetworkAccessManager network_;
    QNetworkReply *reply_ = nullptr;
    QByteArray metadata_;
    bool initialized_ = false;
    bool manual_ = false;
    bool busy_ = false;
    bool cancelled_ = false;
    GitHubRelease::Release release_;
    std::unique_ptr<QTemporaryDir> directory_;
    std::unique_ptr<QTemporaryDir> staging_;
    QFile file_;
    QCryptographicHash hash_{QCryptographicHash::Sha256};
    qint64 downloaded_ = 0;
    QString downloadError_;
    std::unique_ptr<QProgressDialog> progress_;
};

void GitHubUpdateBackend::cleanup()
{
    initialized_ = false;
    if (reply_) {
        disconnect(reply_, nullptr, this, nullptr);
        reply_->abort();
        reply_->deleteLater();
        reply_ = nullptr;
    }
    file_.close();
    progress_.reset();
    directory_.reset();
    staging_.reset();
}

bool GitHubUpdateBackend::checkForUpdates()
{
    check(false);
    return true;
}

void GitHubUpdateBackend::performUIUpdate()
{
    check(true);
}

void GitHubUpdateBackend::check(bool manual)
{
    if (!initialized_) {
        return;
    }
    if (busy_) {
        if (reply_ && !directory_) {
            manual_ |= manual;
        }
        return;
    }

    busy_ = true;
    manual_ = manual;
    metadata_.clear();
    const bool development = prefs.gui_update_channel == UPDATE_CHANNEL_DEVELOPMENT;
    auto request = requestFor(GitHubRelease::apiUrl(development));
    request.setRawHeader("Accept", "application/vnd.github+json");
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::SameOriginRedirectPolicy);
    auto *reply = reply_ = network_.get(request);
    reply->setReadBufferSize(64 * 1024);
    auto read = [this, reply]() {
        metadata_.append(reply->readAll());
        if (metadata_.size() > (2 << 20) && !reply->isFinished()) {
            reply->abort();
        }
    };
    connect(reply, &QNetworkReply::readyRead, this, read);
    connect(reply, &QNetworkReply::finished, this, [this, reply, development, read]() {
        read();
        reply_ = nullptr;
        reply->deleteLater();
        const bool oversized = metadata_.size() > (2 << 20);
        const auto release = oversized ? GitHubRelease::Release() : GitHubRelease::parse(metadata_, development, platform_);
        metadata_.clear();
        QString error;
        if (reply->error() != QNetworkReply::NoError) {
            error = reply->errorString();
        } else if (release.version.isEmpty()) {
            error = tr("GitHub returned invalid release information.");
        }
        finishCheck(error, release);
    });
}

void GitHubUpdateBackend::finishCheck(const QString &error, const GitHubRelease::Release &release)
{
    const QString title = tr("Software Update");
    auto *updates = SoftwareUpdate::instance();
    const QString current = QString::fromLatin1(application_version());
    const bool newer = QVersionNumber::fromString(release.version) > QVersionNumber::fromString(current);
    if (!error.isEmpty()) {
        emit updates->updateCheckFailed(error);
        if (manual_) {
            QMessageBox::warning(QApplication::activeWindow(), title, error);
        }
    } else if (!newer) {
        emit updates->updateEngaged();
        if (manual_) {
            QMessageBox::information(QApplication::activeWindow(), title,
                                     tr("Wireshark %1 is up to date.").arg(current));
        }
    } else if (release.download.isEmpty()) {
        const auto message = tr("Wireshark %1 does not have a verified installer for this platform.").arg(release.version);
        emit updates->updateCheckFailed(message);
        if (manual_) {
            QMessageBox::warning(QApplication::activeWindow(), title, message);
        }
    } else {
        emit updates->updateAvailable(release.version, release.page.toString());
        if (manual_) {
            QMessageBox prompt(QMessageBox::Question, title,
                tr("Wireshark %1 is available on GitHub. You are running %2.").arg(release.version, current),
                QMessageBox::Cancel, QApplication::activeWindow());
            auto *installButton = prompt.addButton(tr("Download and Install"), QMessageBox::AcceptRole);
            auto *notes = prompt.addButton(tr("Release Notes"), QMessageBox::ActionRole);
            prompt.setDefaultButton(installButton);
            prompt.exec();
            if (prompt.clickedButton() == notes) {
                QDesktopServices::openUrl(release.page);
            } else if (prompt.clickedButton() == installButton) {
                download(release);
                return;
            }
        }
    }
    busy_ = false;
}

void GitHubUpdateBackend::download(const GitHubRelease::Release &release)
{
    release_ = release;
    directory_ = std::make_unique<QTemporaryDir>();
    if (!directory_->isValid()) {
        complete(tr("Could not create a temporary directory for the update."));
        return;
    }

    file_.setFileName(directory_->filePath(release.download.fileName()));
    if (!file_.open(QIODevice::WriteOnly | QIODevice::NewOnly)) {
        complete(file_.errorString());
        return;
    }

    downloaded_ = 0;
    hash_.reset();
    downloadError_.clear();
    cancelled_ = false;
    progress_ = std::make_unique<QProgressDialog>(
        tr("Downloading Wireshark %1…").arg(release.version), tr("Cancel"), 0, static_cast<int>(release.size));
    progress_->setWindowTitle(tr("Software Update"));
    progress_->setAutoReset(false);
    progress_->setAutoClose(false);

    auto request = requestFor(release.download);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::UserVerifiedRedirectPolicy);
    auto *reply = reply_ = network_.get(request);
    reply->setReadBufferSize(64 * 1024);
    connect(reply, &QNetworkReply::redirected, this, [this, reply](const QUrl &url) {
        if (GitHubRelease::isDownloadHost(reply->url().resolved(url))) {
            emit reply->redirectAllowed();
        } else {
            downloadError_ = tr("The update download was redirected to an unexpected server.");
            reply->abort();
        }
    });
    connect(reply, &QNetworkReply::readyRead, this, &GitHubUpdateBackend::readDownload);
    connect(reply, &QNetworkReply::finished, this, &GitHubUpdateBackend::finishDownload);
    connect(progress_.get(), &QProgressDialog::canceled, this, [this, reply]() {
        cancelled_ = true;
        // Abort on the next event-loop turn so the dialog can finish cancelling.
        QMetaObject::invokeMethod(reply, [reply]() { reply->abort(); }, Qt::QueuedConnection);
    });
    progress_->setValue(0);
    progress_->show();
}

void GitHubUpdateBackend::readDownload()
{
    if (!downloadError_.isEmpty() || cancelled_) {
        return;
    }
    const QByteArray bytes = reply_->readAll();
    if (bytes.size() > release_.size - downloaded_) {
        downloadError_ = tr("The update is larger than the size published by GitHub.");
    } else if (file_.write(bytes) != bytes.size()) {
        downloadError_ = file_.errorString();
    }
    if (!downloadError_.isEmpty()) {
        if (!reply_->isFinished()) {
            reply_->abort();
        }
        return;
    }

    hash_.addData(bytes);
    downloaded_ += bytes.size();
    progress_->setValue(static_cast<int>(downloaded_));
}

void GitHubUpdateBackend::finishDownload()
{
    if (reply_->error() == QNetworkReply::NoError) {
        readDownload();
    } else if (downloadError_.isEmpty()) {
        downloadError_ = reply_->errorString();
    }

    reply_->deleteLater();
    reply_ = nullptr;
    if (downloadError_.isEmpty() && !file_.flush()) {
        downloadError_ = file_.errorString();
    }
    file_.close();
    progress_.reset();

    if (cancelled_) {
        complete();
    } else if (!downloadError_.isEmpty()) {
        complete(downloadError_);
    } else if (downloaded_ != release_.size || hash_.result() != release_.sha256) {
        complete(tr("The update does not match the size and SHA-256 checksum published by GitHub."));
    } else {
        install();
    }
}

bool GitHubUpdateBackend::prepareShutdown()
{
    const auto event = SoftwareUpdate::instance()->requestShutdown();
    if (!event.isAccepted()) {
        complete(event.reason().isEmpty() ? tr("Please close the current capture before updating.") : event.reason());
        return false;
    }
    return true;
}

void GitHubUpdateBackend::runTool(const QString &program, const QStringList &arguments,
                                 const std::function<void(bool, QString)> &done)
{
    auto *process = new QProcess(this);
    process->setProcessChannelMode(QProcess::MergedChannels);
    process->setWorkingDirectory(QStringLiteral("/"));
    connect(process, &QProcess::errorOccurred, this, [process, done](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart) {
            process->deleteLater();
            done(false, process->errorString());
        }
    });
    connect(process, &QProcess::finished, this, [process, done](int code, QProcess::ExitStatus status) {
        process->deleteLater();
        done(status == QProcess::NormalExit && code == 0,
             QString::fromLocal8Bit(process->readAll()).trimmed().right(1500));
    });
    process->start(program, arguments, QIODevice::ReadOnly);
}

void GitHubUpdateBackend::install()
{
    const QString package = file_.fileName();
#ifdef Q_OS_WIN
    if (prepareShutdown()) {
        if (QDesktopServices::openUrl(QUrl::fromLocalFile(package))) {
            // The installer runs after Wireshark exits and still needs the executable.
            directory_->setAutoRemove(false);
            QCoreApplication::quit();
        } else {
            create_app_running_mutex();
            complete(tr("Windows could not start the Wireshark installer."));
        }
    }
#elif defined(Q_OS_MACOS)
    const QString currentApp = QDir::cleanPath(QCoreApplication::applicationDirPath() + QStringLiteral("/../.."));
    const bool appBundle = currentApp.endsWith(QStringLiteral(".app"), Qt::CaseInsensitive);
    if (appBundle) {
        // The old and new bundles must be on the same volume for an atomic swap.
        staging_ = std::make_unique<QTemporaryDir>(QFileInfo(currentApp).absolutePath()
            + QStringLiteral("/.wireshark-update-XXXXXX"));
    }
    const bool canReplace = staging_ && staging_->isValid();
    const QString destination = canReplace ? staging_->path() : directory_->path();
    const QString newApp = QDir(destination).filePath(QStringLiteral("Wireshark.app"));
    runTool(QStringLiteral("/usr/bin/ditto"), {QStringLiteral("-x"), QStringLiteral("-k"), package, destination},
        [this, canReplace, currentApp, newApp](bool ok, const QString &details) {
            if (!ok) {
                complete(tr("Could not extract the update. %1").arg(details));
                return;
            }
            QSettings info(newApp + QStringLiteral("/Contents/Info.plist"), QSettings::NativeFormat);
            if (QFileInfo(newApp).isSymLink()
                || info.value(QStringLiteral("CFBundleIdentifier")).toString() != QStringLiteral("org.wireshark.Wireshark")
                || info.value(QStringLiteral("CFBundleShortVersionString")).toString() != release_.version) {
                complete(tr("The downloaded application does not match the selected Wireshark release."));
                return;
            }
            runTool(QStringLiteral("/usr/bin/codesign"),
                {QStringLiteral("--verify"), QStringLiteral("--deep"), QStringLiteral("--strict"), newApp},
                [this, canReplace, currentApp, newApp](bool valid, const QString &output) {
                    if (!valid) {
                        complete(tr("Could not verify the application bundle. %1").arg(output));
                    } else if (!canReplace) {
                        showPackage(tr("Wireshark cannot replace this application in place. Quit Wireshark, then move the downloaded application to Applications."));
                    } else if (prepareShutdown()) {
                        QLockFile lock(currentApp + QStringLiteral(".update.lock"));
                        if (!lock.tryLock(0)) {
                            complete(tr("Another Wireshark update is already in progress."));
                            return;
                        }
                        const QSettings installed(currentApp + QStringLiteral("/Contents/Info.plist"), QSettings::NativeFormat);
                        const auto installedVersion = QVersionNumber::fromString(
                            installed.value(QStringLiteral("CFBundleShortVersionString")).toString());
                        if (installedVersion >= QVersionNumber::fromString(release_.version)) {
                            complete(tr("Wireshark %1 is up to date.").arg(installedVersion.toString()));
                            return;
                        }
                        if (renameatx_np(AT_FDCWD, QFile::encodeName(newApp).constData(),
                                        AT_FDCWD, QFile::encodeName(currentApp).constData(), RENAME_SWAP) != 0) {
                            showPackage(tr("Wireshark cannot replace this application in place. Quit Wireshark, then move the downloaded application to Applications."));
                            return;
                        }
                        lock.unlock();
                        QMessageBox::information(QApplication::activeWindow(), tr("Software Update"),
                            tr("Wireshark %1 was installed. Reopen Wireshark to use it.").arg(release_.version));
                        QCoreApplication::quit();
                    }
                });
        });
#elif defined(Q_OS_LINUX)
    const QString destination = directory_->path();
    const QString packages = destination + QStringLiteral("/Wireshark-%1-linux-x86_64").arg(release_.version);
    runTool(QStringLiteral("/usr/bin/tar"), {QStringLiteral("-xzf"), package,
            QStringLiteral("-C"), destination, QStringLiteral("--no-same-owner"), QStringLiteral("--no-same-permissions")},
        [this, packages](bool ok, const QString &details) {
            if (!ok) {
                complete(tr("Could not extract the update. %1").arg(details));
                return;
            }

            const QDir packageDir(packages);
            QStringList files;
            for (const auto &pattern : {"wireshark_*", "wireshark-common_*", "tshark_*",
                     "libwireshark[0-9]*", "libwiretap[0-9]*", "libwsutil[0-9]*",
                     "libuiqt-plugin[0-9]*", "libwireshark-data_*"}) {
                const auto matches = packageDir.entryList({QString::fromLatin1(pattern) + QStringLiteral(".deb")},
                                                          QDir::Files | QDir::NoSymLinks);
                if (matches.size() != 1) {
                    complete(tr("The Ubuntu update does not contain the expected packages."));
                    return;
                }
                files.append(packageDir.absoluteFilePath(matches.constFirst()));
            }

            if (!QFileInfo(QStringLiteral("/usr/bin/pkexec")).isExecutable()) {
                showPackage(tr("Administrator authentication is unavailable. Follow the package installation instructions in BUILD-INFO.txt."));
                return;
            }
            if (!prepareShutdown()) {
                return;
            }

            progress_ = std::make_unique<QProgressDialog>(tr("Installing Wireshark %1…").arg(release_.version),
                QString(), 0, 0);
            progress_->setCancelButton(nullptr);
            progress_->setWindowFlags(Qt::Dialog | Qt::CustomizeWindowHint | Qt::WindowTitleHint);
            progress_->setWindowTitle(tr("Software Update"));
            progress_->setWindowModality(Qt::ApplicationModal);
            progress_->show();

            // apt can still be running if the window manager logs the user out.
            directory_->setAutoRemove(false);
            runTool(QStringLiteral("/usr/bin/pkexec"),
                QStringList{QStringLiteral("/usr/bin/apt-get"), QStringLiteral("install"),
                    QStringLiteral("--yes"), QStringLiteral("--no-remove"), QStringLiteral("--no-install-recommends")} + files,
                [this](bool installed, const QString &output) {
                    progress_.reset();
                    if (directory_) {
                        directory_->setAutoRemove(true);
                    }
                    if (installed) {
                        QMessageBox::information(QApplication::activeWindow(), tr("Software Update"),
                            tr("Wireshark %1 was installed. Reopen Wireshark to use it.").arg(release_.version));
                        QCoreApplication::quit();
                    } else {
                        complete(tr("Could not install the Ubuntu update. %1").arg(output));
                    }
                });
        });
#endif
}

void GitHubUpdateBackend::showPackage(const QString &explanation)
{
    auto *folder = staging_ && staging_->isValid() ? staging_.get() : directory_.get();
    folder->setAutoRemove(false);
    QMessageBox message(QMessageBox::Information, tr("Software Update"), explanation,
                        QMessageBox::Close, QApplication::activeWindow());
    message.setTextFormat(Qt::PlainText);
    message.setInformativeText(folder->path());
    auto *open = message.addButton(tr("Open Download Folder"), QMessageBox::ActionRole);
    message.exec();
    if (message.clickedButton() == open) {
        QDesktopServices::openUrl(QUrl::fromLocalFile(folder->path()));
    }
    complete();
}

void GitHubUpdateBackend::complete(const QString &error)
{
    file_.close();
    progress_.reset();
    staging_.reset();
    directory_.reset();
    if (!error.isEmpty()) {
        QMessageBox message(QMessageBox::Warning, tr("Software Update"), error,
                            QMessageBox::Ok, QApplication::activeWindow());
        message.setTextFormat(Qt::PlainText);
        message.exec();
    }
    busy_ = false;
}

} // namespace

bool supportsGitHubUpdates()
{
    return application_flavor_is_wireshark() && currentPlatform().has_value();
}

SoftwareUpdateBackend *createGitHubUpdateBackend()
{
    return new GitHubUpdateBackend(currentPlatform().value());
}

#include "software_update_backend_github.moc"
