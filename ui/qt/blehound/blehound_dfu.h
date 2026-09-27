/** @file
 *
 * USB firmware update (DFU) of BLEhound dongles: a worker that drives one
 * board through the firmware loader over SMP, and the dialog around it.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#pragma once

#include <QByteArray>
#include <QDialog>
#include <QStringList>
#include <QThread>

class QCheckBox;
class QLineEdit;
class QListWidget;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;

namespace BLEhound {

class NativeSerial;

/**
 * Updates one board. Steps: send BH_CMD_ENTER_DFU on the capture port, wait
 * for the loader to enumerate (BH_USB_PID_LOADER), upload the signed app
 * image over SMP, reset, wait for the sniffer port to come back.
 * The capture port must not be in use (the device manager's idle scanner is
 * paused by the dialog).
 */
class DfuWorker : public QThread
{
    Q_OBJECT

public:
    DfuWorker(const QString &capture_port, const QByteArray &image, QObject *parent = nullptr);

    /** Serial ports of boards currently in the loader. */
    static QStringList loaderPorts();

signals:
    void progress(int percent, const QString &message);
    void done(bool ok, const QString &message);

protected:
    void run() override;

private:
    bool enterLoader(QString *loader_port);
    bool openLoader(NativeSerial &port, const QString &path);
    bool transact(NativeSerial &port, const QByteArray &request, uint8_t seq,
                  QByteArray *reply_payload, int timeout_ms);
    bool upload(NativeSerial &port, uint8_t *seq);
    bool waitForApp(const QString &loader_port);

    QString capture_port_;
    QByteArray image_;
};

/** Pick an image and update the selected boards one after another. */
class DfuDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DfuDialog(QWidget *parent = nullptr);

    /**
     * Developer self-test: with BLEHOUND_DFU_AUTOTEST=<image.bin> in the environment,
     * open the dialog, select every board, run the update and exit the application
     * with 0 (all boards updated) or 1. Same code path as the button.
     */
    static void autoTestIfRequested(QWidget *parent);

private slots:
    void browse();
    void start();
    void onProgress(int percent, const QString &message);
    void onDone(bool ok, const QString &message);

private:
    void log(const QString &line);
    void nextBoard();
    void finish();
    void updateStartButton();

    QLineEdit *image_path_;
    QListWidget *boards_;
    QProgressBar *progress_;
    QPlainTextEdit *log_;
    QPushButton *start_;
    QPushButton *close_;
    QByteArray image_;
    QStringList queue_;
    int total_ = 0;
    int failed_ = 0;
    DfuWorker *worker_ = nullptr;
    bool running_ = false;
    bool auto_test_ = false;
};

} // namespace BLEhound
