/* dfu_cli.c
 * Command-line USB DFU for the BLEhound dongle using libblehound's SMP code.
 * Same protocol code as the GUI's "Update firmware…" dialog; no nrfutil needed.
 *
 *   blehound_dfu ports                           list serial ports; BLEhound app / loader ports are marked
 *   blehound_dfu update <capture port>|all <app.bin>
 *                                                enter the loader, upload, reset, wait for the app to return
 *   blehound_dfu enter <capture port>            send BH_CMD_ENTER_DFU (the board reboots into the loader)
 *   blehound_dfu list  <loader port>             print the images the loader reports
 *   blehound_dfu upload <loader port> <app.bin>  upload the signed app image and reset into it
 *   blehound_dfu reset <loader port>             reset the board (back into the app, or the loader if none)
 *
 * Ports are COMn on Windows, /dev/ttyACMn on Linux, /dev/cu.usbmodem* on macOS.
 * Environment: BH_SMP_LINE_DELAY_US (pause between SMP lines), BH_SMP_MAX_PACKET (cap the chunk size).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blehound/blehound.h"

#ifdef _WIN32
#include <windows.h>
#include <setupapi.h>
#include <initguid.h>
#include <devguid.h>
#include <ntddser.h>
typedef HANDLE port_t;
#define PORT_INVALID INVALID_HANDLE_VALUE
#else
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/serial/IOSerialKeys.h>
#include <IOKit/usb/USBSpec.h>
#else
#include <dirent.h>
#endif
typedef int port_t;
#define PORT_INVALID (-1)
#endif

#define MAX_PORTS 64
#define LOADER_WAIT_MS 15000
#define APP_WAIT_MS 15000
#define POLL_MS 250

typedef struct port_info {
    char name[128];
    uint16_t vid;       /* 0 when unknown */
    uint16_t pid;
} port_info;

/* ------------------------------------------------------------------ portability */

static void sleep_ms(int ms)
{
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    usleep((useconds_t)ms * 1000);
#endif
}

static double now_s(void);

static void sleep_us(long us)
{
#ifdef _WIN32
    /* Sleep() rounds up to the ~15 ms scheduler tick, which would turn the 2 ms pause
     * between SMP lines into 15 ms and a 110 KB upload into 20 s. Spin for short waits. */
    if (us < 20000) {
        double until = now_s() + us / 1e6;
        while (now_s() < until) {
            YieldProcessor();
        }
    } else {
        Sleep((DWORD)((us + 999) / 1000));
    }
#else
    usleep((useconds_t)us);
#endif
}

static double now_s(void)
{
#ifdef _WIN32
    LARGE_INTEGER f, c;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)f.QuadPart;
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
#endif
}

#ifdef _WIN32

static port_t open_port(const char *name)
{
    char path[160];
    DCB dcb;
    COMMTIMEOUTS to;

    snprintf(path, sizeof(path), "\\\\.\\%s", name);
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "%s: cannot open (error %lu)\n", name, GetLastError());
        return PORT_INVALID;
    }
    memset(&dcb, 0, sizeof(dcb));
    dcb.DCBlength = sizeof(dcb);
    (void)GetCommState(h, &dcb);
    dcb.BaudRate = CBR_115200;
    dcb.ByteSize = 8;
    dcb.Parity = NOPARITY;
    dcb.StopBits = ONESTOPBIT;
    dcb.fBinary = TRUE;
    dcb.fDtrControl = DTR_CONTROL_ENABLE;
    dcb.fRtsControl = RTS_CONTROL_ENABLE;
    dcb.fOutxCtsFlow = FALSE;
    dcb.fOutxDsrFlow = FALSE;
    dcb.fDsrSensitivity = FALSE;
    dcb.fOutX = FALSE;
    dcb.fInX = FALSE;
    (void)SetCommState(h, &dcb);
    /* Non-blocking reads: return whatever is there. */
    memset(&to, 0, sizeof(to));
    to.ReadIntervalTimeout = MAXDWORD;
    to.WriteTotalTimeoutConstant = 2000;
    (void)SetCommTimeouts(h, &to);
    PurgeComm(h, PURGE_RXCLEAR | PURGE_TXCLEAR | PURGE_RXABORT | PURGE_TXABORT);
    EscapeCommFunction(h, SETDTR);
    return h;
}

static void close_port(port_t h)
{
    CloseHandle(h);
}

static bool write_raw(port_t h, const uint8_t *data, size_t len)
{
    while (len) {
        DWORD written = 0;
        if (!WriteFile(h, data, (DWORD)len, &written, NULL)) {
            return false;
        }
        data += written;
        len -= written;
    }
    return true;
}

/** Read what is available, waiting at most wait_ms for the first byte. @return bytes read, 0 on timeout. */
static int read_some(port_t h, uint8_t *buf, size_t cap, int wait_ms)
{
    double deadline = now_s() + wait_ms / 1000.0;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(h, buf, (DWORD)cap, &got, NULL)) {
            return -1;
        }
        if (got > 0) {
            return (int)got;
        }
        if (now_s() >= deadline) {
            return 0;
        }
        Sleep(5);
    }
}

/* SetupAPI: every present COM port with its VID/PID (from the hardware id "USB\VID_1915&PID_520F&..."). */
static int list_ports(port_info *out, int max)
{
    int count = 0;
    HDEVINFO set = SetupDiGetClassDevsA(&GUID_DEVINTERFACE_COMPORT, NULL, NULL,
                                        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (set == INVALID_HANDLE_VALUE) {
        return 0;
    }
    SP_DEVINFO_DATA dev;
    dev.cbSize = sizeof(dev);
    for (DWORD i = 0; SetupDiEnumDeviceInfo(set, i, &dev) && count < max; i++) {
        char hwid[512] = "";
        char portname[64] = "";
        DWORD type = 0, size = sizeof(portname);

        HKEY key = SetupDiOpenDevRegKey(set, &dev, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
        if (key == INVALID_HANDLE_VALUE) {
            continue;
        }
        LONG rc = RegQueryValueExA(key, "PortName", NULL, &type, (LPBYTE)portname, &size);
        RegCloseKey(key);
        if (rc != ERROR_SUCCESS || strncmp(portname, "COM", 3) != 0) {
            continue;
        }
        (void)SetupDiGetDeviceRegistryPropertyA(set, &dev, SPDRP_HARDWAREID, NULL, (PBYTE)hwid, sizeof(hwid), NULL);
        port_info *p = &out[count++];
        memset(p, 0, sizeof(*p));
        snprintf(p->name, sizeof(p->name), "%s", portname);
        const char *v = strstr(hwid, "VID_");
        const char *d = strstr(hwid, "PID_");
        if (v && d) {
            p->vid = (uint16_t)strtoul(v + 4, NULL, 16);
            p->pid = (uint16_t)strtoul(d + 4, NULL, 16);
        }
    }
    SetupDiDestroyDeviceInfoList(set);
    return count;
}

#else /* POSIX */

static port_t open_port(const char *path)
{
    int fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    struct termios tio;
    int flags;

    if (fd < 0) {
        perror(path);
        return PORT_INVALID;
    }
    (void)ioctl(fd, TIOCEXCL);
    if (tcgetattr(fd, &tio) == 0) {
        cfmakeraw(&tio);
        cfsetispeed(&tio, B115200);
        cfsetospeed(&tio, B115200);
        tio.c_cflag |= CLOCAL | CREAD;
        tio.c_cc[VMIN] = 0;
        tio.c_cc[VTIME] = 0;
        (void)tcsetattr(fd, TCSANOW, &tio);
    }
    flags = TIOCM_DTR;
    (void)ioctl(fd, TIOCMBIS, &flags);
    return fd;
}

static void close_port(port_t fd)
{
    close(fd);
}

static bool write_raw(port_t fd, const uint8_t *data, size_t len)
{
    while (len) {
        ssize_t n = write(fd, data, len);
        if (n < 0) {
            if (errno == EAGAIN) { usleep(1000); continue; }
            return false;
        }
        data += n;
        len -= (size_t)n;
    }
    return true;
}

static int read_some(port_t fd, uint8_t *buf, size_t cap, int wait_ms)
{
    struct pollfd pfd = { fd, POLLIN, 0 };
    int rc = poll(&pfd, 1, wait_ms);
    if (rc < 0) return -1;
    if (rc == 0) return 0;
    ssize_t n = read(fd, buf, cap);
    if (n < 0) return (errno == EAGAIN) ? 0 : -1;
    return (int)n;
}

#ifdef __APPLE__

static bool entry_u16(io_object_t entry, CFStringRef key, uint16_t *val)
{
    CFTypeRef ref = IORegistryEntrySearchCFProperty(entry, kIOServicePlane, key, kCFAllocatorDefault,
                                                    kIORegistryIterateRecursively | kIORegistryIterateParents);
    if (!ref) return false;
    int32_t v = 0;
    bool ok = CFGetTypeID(ref) == CFNumberGetTypeID() && CFNumberGetValue(ref, kCFNumberSInt32Type, &v);
    CFRelease(ref);
    if (ok) *val = (uint16_t)v;
    return ok;
}

/* IOKit: every IOSerialBSDClient callout device, VID/PID from the USB parent. */
static int list_ports(port_info *out, int max)
{
    int count = 0;
    io_iterator_t it;
    CFMutableDictionaryRef match = IOServiceMatching(kIOSerialBSDServiceValue);
    if (!match) return 0;
    CFDictionarySetValue(match, CFSTR(kIOSerialBSDTypeKey), CFSTR(kIOSerialBSDAllTypes));
    if (IOServiceGetMatchingServices(kIOMasterPortDefault, match, &it) != KERN_SUCCESS) {
        return 0;
    }
    io_object_t svc;
    while ((svc = IOIteratorNext(it)) && count < max) {
        CFTypeRef path = IORegistryEntryCreateCFProperty(svc, CFSTR(kIOCalloutDeviceKey), kCFAllocatorDefault, 0);
        if (path && CFGetTypeID(path) == CFStringGetTypeID()) {
            port_info *p = &out[count];
            memset(p, 0, sizeof(*p));
            if (CFStringGetCString(path, p->name, sizeof(p->name), kCFStringEncodingUTF8)) {
                (void)entry_u16(svc, CFSTR(kUSBVendorID), &p->vid);
                (void)entry_u16(svc, CFSTR(kUSBProductID), &p->pid);
                count++;
            }
        }
        if (path) CFRelease(path);
        IOObjectRelease(svc);
    }
    IOObjectRelease(it);
    return count;
}

#else /* Linux */

static bool read_hex_file(const char *path, uint16_t *val)
{
    FILE *f = fopen(path, "r");
    unsigned v = 0;
    if (!f) return false;
    bool ok = fscanf(f, "%x", &v) == 1;
    fclose(f);
    if (ok) *val = (uint16_t)v;
    return ok;
}

/* sysfs: /dev/ttyACM* and /dev/ttyUSB*, VID/PID from the USB device two levels up. */
static int list_ports(port_info *out, int max)
{
    int count = 0;
    DIR *d = opendir("/sys/class/tty");
    struct dirent *e;
    if (!d) return 0;
    while ((e = readdir(d)) && count < max) {
        if (strncmp(e->d_name, "ttyACM", 6) != 0 && strncmp(e->d_name, "ttyUSB", 6) != 0) {
            continue;
        }
        port_info *p = &out[count++];
        char path[512];
        memset(p, 0, sizeof(*p));
        snprintf(p->name, sizeof(p->name), "/dev/%s", e->d_name);
        snprintf(path, sizeof(path), "/sys/class/tty/%s/device/../idVendor", e->d_name);
        (void)read_hex_file(path, &p->vid);
        snprintf(path, sizeof(path), "/sys/class/tty/%s/device/../idProduct", e->d_name);
        (void)read_hex_file(path, &p->pid);
    }
    closedir(d);
    return count;
}

#endif /* __APPLE__ */
#endif /* _WIN32 */

/* ------------------------------------------------------------------ SMP transport */

/*
 * Write SMP lines one at a time with a pause in between: the loader keeps only
 * CONFIG_UART_MCUMGR_RX_BUF_COUNT (2) line buffers and drops lines that arrive
 * before the work queue has decoded the previous ones ("Insufficient buffers").
 */
static bool write_all(port_t h, const uint8_t *data, size_t len)
{
    const char *env = getenv("BH_SMP_LINE_DELAY_US");
    long delay = env ? atol(env) : BH_SMP_LINE_DELAY_US;
    size_t start = 0;

    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\n') {
            if (!write_raw(h, data + start, i + 1 - start)) {
                return false;
            }
            start = i + 1;
            if (delay > 0) {
                sleep_us(delay);
            }
        }
    }
    return start == len || write_raw(h, data + start, len - start);
}

typedef struct reply {
    bool have;
    bh_smp_hdr hdr;
    uint8_t payload[BH_SMP_MAX_PACKET];
    size_t len;
} reply;

static void on_packet(void *ctx, const bh_smp_hdr *hdr, const uint8_t *payload, size_t len)
{
    reply *r = ctx;

    r->have = true;
    r->hdr = *hdr;
    memcpy(r->payload, payload, len);
    r->len = len;
}

/** Send one request and wait for the reply with the same sequence number. */
static bool transact(port_t h, const uint8_t *req, size_t req_len, uint8_t seq, reply *r, int timeout_ms)
{
    bh_smp_deframer d;
    uint8_t buf[512];
    double deadline = now_s() + timeout_ms / 1000.0;

    bh_smp_deframer_init(&d);
    r->have = false;
    if (!write_all(h, req, req_len)) {
        return false;
    }
    while (now_s() < deadline) {
        int n = read_some(h, buf, sizeof(buf), 50);
        if (n < 0) return false;
        if (n == 0) continue;
        bh_smp_deframer_feed(&d, buf, (size_t)n, on_packet, r);
        if (r->have) {
            if (r->hdr.seq == seq) {
                return true;
            }
            r->have = false;
        }
    }
    return false;
}

/* ------------------------------------------------------------------ port roles */

static const char *role_of(const port_info *p)
{
    if (p->vid == BH_USB_VID && p->pid == BH_USB_PID) return "BLEhound app";
    if (p->vid == BH_USB_VID && p->pid == BH_USB_PID_LOADER) return "BLEhound loader";
    return "";
}

static int ports_with_pid(uint16_t pid, port_info *out, int max)
{
    port_info all[MAX_PORTS];
    int n = list_ports(all, MAX_PORTS), count = 0;
    for (int i = 0; i < n && count < max; i++) {
        if (all[i].vid == BH_USB_VID && all[i].pid == pid) {
            out[count++] = all[i];
        }
    }
    return count;
}

static bool has_port(const port_info *list, int n, const char *name)
{
    for (int i = 0; i < n; i++) {
        if (strcmp(list[i].name, name) == 0) return true;
    }
    return false;
}

/* ------------------------------------------------------------------ commands */

static int cmd_ports(void)
{
    port_info all[MAX_PORTS];
    int n = list_ports(all, MAX_PORTS);

    for (int i = 0; i < n; i++) {
        if (all[i].vid) {
            printf("%-24s %04x:%04x  %s\n", all[i].name, all[i].vid, all[i].pid, role_of(&all[i]));
        } else {
            printf("%-24s\n", all[i].name);
        }
    }
    if (n == 0) {
        printf("no serial ports\n");
    }
    return 0;
}

static bool send_enter_dfu(const char *port)
{
    port_t h = open_port(port);
    uint8_t line[16];
    size_t n;

    if (h == PORT_INVALID) return false;
    sleep_ms(100);
    n = bh_cmd_build(BH_CMD_ENTER_DFU, NULL, 0, line, sizeof(line));
    line[n++] = 0x00;
    bool ok = write_all(h, line, n);
    sleep_ms(200);
    close_port(h);
    return ok;
}

static int cmd_enter(const char *port)
{
    bool ok = send_enter_dfu(port);
    printf(ok ? "ENTER_DFU sent\n" : "write failed\n");
    return ok ? 0 : 1;
}

static void print_images(const reply *r)
{
    bh_smp_image imgs[4];
    int count = bh_smp_rsp_images(r->payload, r->len, imgs, 4);

    if (count < 0) {
        printf("malformed image list\n");
        return;
    }
    for (int i = 0; i < count; i++) {
        printf("slot %u: version %s%s%s%s\n", imgs[i].slot, imgs[i].version,
               imgs[i].active ? " active" : "", imgs[i].confirmed ? " confirmed" : "",
               imgs[i].bootable ? " bootable" : "");
    }
}

static int cmd_list(const char *port)
{
    port_t h = open_port(port);
    uint8_t req[64];
    reply r;

    if (h == PORT_INVALID) return 1;
    size_t n = bh_smp_req_image_state(1, req, sizeof(req));
    if (!transact(h, req, n, 1, &r, 3000)) {
        printf("no reply from the loader\n");
        close_port(h);
        return 1;
    }
    print_images(&r);
    close_port(h);
    return 0;
}

static int cmd_reset(const char *port)
{
    port_t h = open_port(port);
    uint8_t req[64];
    reply r;

    if (h == PORT_INVALID) return 1;
    size_t n = bh_smp_req_reset(1, req, sizeof(req));
    bool ok = transact(h, req, n, 1, &r, 3000);
    printf(ok ? "reset acknowledged\n" : "no reply to reset (the board may have reset already)\n");
    close_port(h);
    return 0;
}

static uint8_t *read_image(const char *path, long *size)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    *size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *image = malloc(*size > 0 ? (size_t)*size : 1);
    if (!image || *size <= 0 || fread(image, 1, (size_t)*size, f) != (size_t)*size) {
        printf("%s: read failed\n", path);
        fclose(f);
        free(image);
        return NULL;
    }
    fclose(f);
    return image;
}

/** Upload the image through an open loader port and ask for a reset. */
static bool upload_image(port_t h, const uint8_t *image, long size)
{
    uint8_t req[BH_SMP_MAX_ENCODED];
    reply r;
    uint8_t seq = 1;
    uint32_t buf_size = BH_SMP_DEFAULT_BUF_SIZE;

    size_t n = bh_smp_req_params(seq, req, sizeof(req));
    if (transact(h, req, n, seq, &r, 2000)) {
        (void)bh_smp_rsp_params(r.payload, r.len, &buf_size, NULL);
    }
    const char *cap_env = getenv("BH_SMP_MAX_PACKET");
    if (cap_env && (uint32_t)atoi(cap_env) < buf_size) {
        buf_size = (uint32_t)atoi(cap_env);
    }
    size_t chunk = bh_smp_upload_chunk_max(buf_size);
    printf("loader buf_size %u -> chunk %u bytes, image %ld bytes\n", buf_size, (unsigned)chunk, size);

    double t0 = now_s();
    uint32_t off = 0;
    while (off < (uint32_t)size) {
        size_t len = (uint32_t)size - off < chunk ? (size_t)((uint32_t)size - off) : chunk;
        seq++;
        n = bh_smp_req_image_upload(seq, off, (uint32_t)size, image + off, len, req, sizeof(req));
        if (!transact(h, req, n, seq, &r, 5000)) {
            printf("\nno reply at offset %u\n", off);
            return false;
        }
        int32_t rc = 0;
        uint32_t next = off;
        if (!bh_smp_rsp_status(r.payload, r.len, &rc, &next) || rc != 0) {
            printf("\nloader rejected chunk at %u: rc %d\n", off, rc);
            return false;
        }
        if (next <= off) {
            printf("\nloader did not advance (off %u -> %u)\n", off, next);
            return false;
        }
        off = next;
        printf("\r%u / %ld bytes", off, size);
        fflush(stdout);
    }
    printf("\nuploaded in %.2f s\n", now_s() - t0);

    seq++;
    n = bh_smp_req_image_state(seq, req, sizeof(req));
    if (transact(h, req, n, seq, &r, 3000)) {
        print_images(&r);
    }
    seq++;
    n = bh_smp_req_reset(seq, req, sizeof(req));
    /* The board resets right away; the reply may never arrive. */
    printf(transact(h, req, n, seq, &r, 1500) ? "reset acknowledged\n" : "reset sent\n");
    return true;
}

static int cmd_upload(const char *port, const char *path)
{
    long size;
    uint8_t *image = read_image(path, &size);
    if (!image) return 1;

    port_t h = open_port(port);
    if (h == PORT_INVALID) { free(image); return 1; }
    bool ok = upload_image(h, image, size);
    close_port(h);
    free(image);
    return ok ? 0 : 1;
}

/**
 * Full update of one board: ENTER_DFU on the capture port, find the loader port, upload,
 * reset, wait for the capture port to come back. Mirrors DfuWorker in the GUI.
 */
static int update_one(const char *capture_port, const uint8_t *image, long size)
{
    port_info before[MAX_PORTS];
    int nbefore = ports_with_pid(BH_USB_PID_LOADER, before, MAX_PORTS);
    char loader[128] = "";

    if (has_port(before, nbefore, capture_port)) {
        printf("== %s: already in the loader\n", capture_port);
        snprintf(loader, sizeof(loader), "%s", capture_port);
    } else {
        printf("== %s: entering the loader\n", capture_port);
        if (!send_enter_dfu(capture_port)) {
            printf("!! %s: cannot send ENTER_DFU\n", capture_port);
            return 1;
        }
        double deadline = now_s() + LOADER_WAIT_MS / 1000.0;
        while (now_s() < deadline && !loader[0]) {
            sleep_ms(POLL_MS);
            port_info now[MAX_PORTS];
            int nnow = ports_with_pid(BH_USB_PID_LOADER, now, MAX_PORTS);
            if (has_port(now, nnow, capture_port)) {
                /* macOS: the same name for the same USB location */
                snprintf(loader, sizeof(loader), "%s", capture_port);
                break;
            }
            int fresh = 0;
            const char *fresh_name = NULL;
            for (int i = 0; i < nnow; i++) {
                if (!has_port(before, nbefore, now[i].name)) {
                    fresh++;
                    fresh_name = now[i].name;
                }
            }
            if (fresh == 1) {
                snprintf(loader, sizeof(loader), "%s", fresh_name);
            }
        }
        if (!loader[0]) {
            printf("!! %s: no \"%s\" port appeared\n", capture_port, BH_USB_PRODUCT_LOADER);
            return 1;
        }
    }
    printf("== %s: loader on %s\n", capture_port, loader);

    /* The port node exists a little before it accepts opens. */
    port_t h = PORT_INVALID;
    for (double deadline = now_s() + 3.0; now_s() < deadline && h == PORT_INVALID;) {
        h = open_port(loader);
        if (h == PORT_INVALID) sleep_ms(POLL_MS);
    }
    if (h == PORT_INVALID) {
        return 1;
    }
    sleep_ms(100);
    {
        uint8_t junk[256];
        while (read_some(h, junk, sizeof(junk), 50) > 0) { }
    }
    bool ok = upload_image(h, image, size);
    close_port(h);
    if (!ok) {
        printf("!! %s: upload failed; the board stays in the loader, run again\n", capture_port);
        return 1;
    }

    printf("== %s: waiting for the app to come back\n", capture_port);
    for (double deadline = now_s() + APP_WAIT_MS / 1000.0; now_s() < deadline;) {
        sleep_ms(POLL_MS);
        port_info apps[MAX_PORTS];
        int napps = ports_with_pid(BH_USB_PID, apps, MAX_PORTS);
        port_info ldrs[MAX_PORTS];
        int nldrs = ports_with_pid(BH_USB_PID_LOADER, ldrs, MAX_PORTS);
        if (!has_port(ldrs, nldrs, loader) && (has_port(apps, napps, capture_port) || napps > 0)) {
            printf("== %s: done\n", capture_port);
            return 0;
        }
    }
    printf("?? %s: upload finished but the app port did not reappear in time\n", capture_port);
    return 1;
}

static int cmd_update(const char *target, const char *path)
{
    long size;
    uint8_t *image = read_image(path, &size);
    int failures = 0;

    if (!image) return 1;
    if (strcmp(target, "all") == 0) {
        port_info apps[MAX_PORTS];
        int n = ports_with_pid(BH_USB_PID, apps, MAX_PORTS);
        if (n == 0) {
            printf("no BLEhound app port found\n");
            free(image);
            return 1;
        }
        for (int i = 0; i < n; i++) {
            failures += update_one(apps[i].name, image, size) != 0;
            sleep_ms(1000);
        }
        printf("== %d of %d boards updated\n", n - failures, n);
    } else {
        failures = update_one(target, image, size);
    }
    free(image);
    return failures ? 1 : 0;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "ports") == 0) return cmd_ports();
    if (argc >= 3 && strcmp(argv[1], "enter") == 0) return cmd_enter(argv[2]);
    if (argc >= 3 && strcmp(argv[1], "list") == 0) return cmd_list(argv[2]);
    if (argc >= 3 && strcmp(argv[1], "reset") == 0) return cmd_reset(argv[2]);
    if (argc >= 4 && strcmp(argv[1], "upload") == 0) return cmd_upload(argv[2], argv[3]);
    if (argc >= 4 && strcmp(argv[1], "update") == 0) return cmd_update(argv[2], argv[3]);
    fprintf(stderr,
            "usage: blehound_dfu ports\n"
            "       blehound_dfu update <capture port>|all <app.bin>\n"
            "       blehound_dfu enter <capture port>\n"
            "       blehound_dfu list <loader port>\n"
            "       blehound_dfu reset <loader port>\n"
            "       blehound_dfu upload <loader port> <app.bin>\n");
    return 2;
}
