/* dfu_cli.c
 * Command-line USB DFU for the BLEhound dongle using libblehound's SMP code.
 *
 *   blehound_dfu enter <capture port>            send BH_CMD_ENTER_DFU (the board reboots into the loader)
 *   blehound_dfu list  <loader port>             print the images the loader reports
 *   blehound_dfu upload <loader port> <app.bin>  upload the signed app image and reset into it
 *   blehound_dfu reset <loader port>             reset the board (back into the app, or the loader if none)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "blehound/blehound.h"

static int open_port(const char *path)
{
    int fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    struct termios tio;
    int flags;

    if (fd < 0) {
        perror(path);
        return -1;
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

static bool write_raw(int fd, const uint8_t *data, size_t len)
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

/*
 * Write SMP lines one at a time with a pause in between: the loader keeps only
 * CONFIG_UART_MCUMGR_RX_BUF_COUNT (2) line buffers and drops lines that arrive
 * before the work queue has decoded the previous ones ("Insufficient buffers").
 */
static bool write_all(int fd, const uint8_t *data, size_t len)
{
    const char *env = getenv("BH_SMP_LINE_DELAY_US");
    useconds_t delay = env ? (useconds_t)atoi(env) : BH_SMP_LINE_DELAY_US;
    size_t start = 0;

    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\n') {
            if (!write_raw(fd, data + start, i + 1 - start)) {
                return false;
            }
            start = i + 1;
            if (delay) {
                usleep(delay);
            }
        }
    }
    return start == len || write_raw(fd, data + start, len - start);
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
static bool transact(int fd, const uint8_t *req, size_t req_len, uint8_t seq, reply *r, int timeout_ms)
{
    bh_smp_deframer d;
    uint8_t buf[512];
    struct pollfd pfd = { fd, POLLIN, 0 };
    int waited = 0;

    bh_smp_deframer_init(&d);
    r->have = false;
    if (!write_all(fd, req, req_len)) {
        return false;
    }
    while (waited < timeout_ms) {
        int rc = poll(&pfd, 1, 50);
        if (rc < 0) return false;
        if (rc == 0) { waited += 50; continue; }
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) { waited += 50; continue; }
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

static int cmd_enter(const char *port)
{
    int fd = open_port(port);
    uint8_t line[16];
    size_t n;

    if (fd < 0) return 1;
    usleep(100000);
    n = bh_cmd_build(BH_CMD_ENTER_DFU, NULL, 0, line, sizeof(line));
    line[n++] = 0x00;
    bool ok = write_all(fd, line, n);
    usleep(200000);
    close(fd);
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
    int fd = open_port(port);
    uint8_t req[64];
    reply r;

    if (fd < 0) return 1;
    size_t n = bh_smp_req_image_state(1, req, sizeof(req));
    if (!transact(fd, req, n, 1, &r, 3000)) {
        printf("no reply from the loader\n");
        close(fd);
        return 1;
    }
    print_images(&r);
    close(fd);
    return 0;
}

static int cmd_reset(const char *port)
{
    int fd = open_port(port);
    uint8_t req[64];
    reply r;

    if (fd < 0) return 1;
    size_t n = bh_smp_req_reset(1, req, sizeof(req));
    bool ok = transact(fd, req, n, 1, &r, 3000);
    printf(ok ? "reset acknowledged\n" : "no reply to reset\n");
    close(fd);
    return ok ? 0 : 1;
}

static int cmd_upload(const char *port, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return 1; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *image = malloc((size_t)size);
    if (!image || fread(image, 1, (size_t)size, f) != (size_t)size) { printf("read failed\n"); return 1; }
    fclose(f);

    int fd = open_port(port);
    if (fd < 0) return 1;
    uint8_t req[BH_SMP_MAX_ENCODED];
    reply r;
    uint8_t seq = 1;
    uint32_t buf_size = BH_SMP_DEFAULT_BUF_SIZE;

    size_t n = bh_smp_req_params(seq, req, sizeof(req));
    if (transact(fd, req, n, seq, &r, 2000)) {
        (void)bh_smp_rsp_params(r.payload, r.len, &buf_size, NULL);
    }
    const char *cap_env = getenv("BH_SMP_MAX_PACKET");
    if (cap_env && (uint32_t)atoi(cap_env) < buf_size) {
        buf_size = (uint32_t)atoi(cap_env);
    }
    size_t chunk = bh_smp_upload_chunk_max(buf_size);
    printf("loader buf_size %u -> chunk %zu bytes, image %ld bytes\n", buf_size, chunk, size);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    uint32_t off = 0;
    while (off < (uint32_t)size) {
        size_t len = (uint32_t)size - off < chunk ? (size_t)((uint32_t)size - off) : chunk;
        seq++;
        n = bh_smp_req_image_upload(seq, off, (uint32_t)size, image + off, len, req, sizeof(req));
        if (!transact(fd, req, n, seq, &r, 5000)) {
            printf("\nno reply at offset %u\n", off);
            close(fd);
            return 1;
        }
        int32_t rc = 0;
        uint32_t next = off;
        if (!bh_smp_rsp_status(r.payload, r.len, &rc, &next) || rc != 0) {
            printf("\nloader rejected chunk at %u: rc %d\n", off, rc);
            close(fd);
            return 1;
        }
        if (next <= off) {
            printf("\nloader did not advance (off %u -> %u)\n", off, next);
            close(fd);
            return 1;
        }
        off = next;
        printf("\r%u / %ld bytes", off, size);
        fflush(stdout);
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("\nuploaded in %.2f s\n", (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9);

    seq++;
    n = bh_smp_req_image_state(seq, req, sizeof(req));
    if (transact(fd, req, n, seq, &r, 3000)) {
        print_images(&r);
    }
    seq++;
    n = bh_smp_req_reset(seq, req, sizeof(req));
    if (!transact(fd, req, n, seq, &r, 3000)) {
        printf("no reply to reset (the board may have reset already)\n");
    } else {
        printf("reset acknowledged\n");
    }
    close(fd);
    free(image);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 3 && strcmp(argv[1], "enter") == 0) return cmd_enter(argv[2]);
    if (argc >= 3 && strcmp(argv[1], "list") == 0) return cmd_list(argv[2]);
    if (argc >= 3 && strcmp(argv[1], "reset") == 0) return cmd_reset(argv[2]);
    if (argc >= 4 && strcmp(argv[1], "upload") == 0) return cmd_upload(argv[2], argv[3]);
    fprintf(stderr, "usage: blehound_dfu enter <capture port> | list <loader port> | reset <loader port> | upload <loader port> <app.bin>\n");
    return 2;
}
