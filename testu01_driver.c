/*
 * TestU01 driver for ChaosRNG
 * 连接 RNG 的 TCP GET_SEED 接口，流式拉种子数据
 * 交给 TestU01 跑 SmallCrush / Crush / BigCrush
 *
 * 用法: ./testu01_driver <host> <port> <battery>
 *   battery: 1=SmallCrush  2=Crush  3=BigCrush
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "unif01.h"
#include "bbattery.h"

static int sock_fd = -1;
static unsigned char buf[65536];
static size_t buf_pos = 0;      /* 比特位置 */
static size_t buf_len = 0;      /* 当前缓冲区字节数 */
static unsigned long long total_bits = 0;

static int connect_rng(const char *host, int port) {
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) return -1;
    if (connect(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock_fd);
        sock_fd = -1;
        return -1;
    }
    return 0;
}

static int refill(void) {
    if (sock_fd < 0) return -1;
    const char *cmd = "GET_SEED\n";
    size_t cmd_len = strlen(cmd);
    size_t written = 0;
    while (written < cmd_len) {
        ssize_t n = write(sock_fd, cmd + written, cmd_len - written);
        if (n <= 0) return -1;
        written += n;
    }
    unsigned char hdr[4];
    size_t got = 0;
    while (got < 4) {
        ssize_t n = read(sock_fd, hdr + got, 4 - got);
        if (n <= 0) return -1;
        got += n;
    }
    unsigned int n = ((unsigned int)hdr[0] << 24) |
                     ((unsigned int)hdr[1] << 16) |
                     ((unsigned int)hdr[2] << 8)  |
                     ((unsigned int)hdr[3]);
    if (n == 0 || n > sizeof(buf)) return -1;
    got = 0;
    while (got < n) {
        ssize_t r = read(sock_fd, buf + got, n - got);
        if (r <= 0) return -1;
        got += r;
    }
    buf_pos = 0;
    buf_len = n;
    return 0;
}

/* TestU01 回调：返回 32 位随机数 */
static unsigned int next_bits(void) {
    unsigned int x = 0;
    for (int i = 0; i < 32; i++) {
        if (buf_pos >= buf_len * 8) {
            if (refill() < 0) {
                fprintf(stderr, "RNG connection failed\n");
                exit(1);
            }
        }
        size_t byte_idx = buf_pos / 8;
        size_t bit_idx  = buf_pos % 8;
        int bit = (buf[byte_idx] >> (7 - bit_idx)) & 1;
        x = (x << 1) | (unsigned int)bit;
        buf_pos++;
        total_bits++;
    }
    return x;
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    int port         = argc > 2 ? atoi(argv[2]) : 18888;
    int battery      = argc > 3 ? atoi(argv[3]) : 3;

    if (connect_rng(host, port) < 0) {
        fprintf(stderr, "Cannot connect to %s:%d\n", host, port);
        return 1;
    }
    fprintf(stderr, "[TestU01] Connected to %s:%d\n", host, port);

    unif01_Gen *gen = unif01_CreateExternGenBits("ChaosRNG", next_bits);

    switch (battery) {
        case 1:
            fprintf(stderr, "[TestU01] Battery: SmallCrush\n");
            bbattery_SmallCrush(gen);
            break;
        case 2:
            fprintf(stderr, "[TestU01] Battery: Crush\n");
            bbattery_Crush(gen);
            break;
        case 3:
        default:
            fprintf(stderr, "[TestU01] Battery: BigCrush\n");
            bbattery_BigCrush(gen);
            break;
    }

    unif01_DeleteExternGenBits(gen);
    fprintf(stderr, "[TestU01] Total bits consumed: %llu\n", total_bits);
    return 0;
}
