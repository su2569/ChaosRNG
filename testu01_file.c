/*
 * TestU01 driver — 从本地文件读数据
 *
 * 用法: ./testu01_file <file> <battery>
 *   battery: 1=SmallCrush  2=Crush  3=BigCrush
 *
 * 文件内容: 任意二进制，按比特流喂给 TestU01
 *           (直接读 rng_data.bin 即可，文件里的字节序即比特顺序)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "unif01.h"
#include "bbattery.h"

static FILE *fp = NULL;
static unsigned char buf[1 << 20];   /* 1 MB 缓冲 */
static size_t buf_pos_bits = 0;
static size_t buf_len_bits = 0;
static unsigned long long total_bits = 0;

static int refill(void) {
    if (fp == NULL) return -1;
    size_t n = fread(buf, 1, sizeof(buf), fp);
    if (n == 0) return -1;   /* EOF */
    buf_pos_bits = 0;
    buf_len_bits = n * 8;
    return 0;
}

static unsigned int next_bits(void) {
    unsigned int x = 0;
    for (int i = 0; i < 32; i++) {
        if (buf_pos_bits >= buf_len_bits) {
            if (refill() < 0) {
                /* 文件读完了，回到开头循环 */
                fseek(fp, 0, SEEK_SET);
                if (refill() < 0) {
                    fprintf(stderr, "文件读取失败\n");
                    exit(1);
                }
            }
        }
        size_t byte_idx = buf_pos_bits / 8;
        size_t bit_idx  = buf_pos_bits % 8;
        int b = (buf[byte_idx] >> (7 - bit_idx)) & 1;
        x = (x << 1) | (unsigned int)b;
        buf_pos_bits++;
        total_bits++;
    }
    return x;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "用法: %s <file> [battery=1]\n", argv[0]);
        fprintf(stderr, "  battery: 1=SmallCrush 2=Crush 3=BigCrush\n");
        return 1;
    }
    const char *path = argv[1];
    int battery = argc > 2 ? atoi(argv[2]) : 1;

    fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "无法打开文件: %s\n", path);
        return 1;
    }

    /* 打印文件大小 */
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fprintf(stderr, "[TestU01] 文件: %s (%ld 字节 = %.2f MB)\n",
            path, fsize, fsize / 1024.0 / 1024.0);

    unif01_Gen *gen = unif01_CreateExternGenBits("ChaosRNG-file", next_bits);

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
    fclose(fp);

    fprintf(stderr, "[TestU01] Total bits consumed: %llu (%.2f MB)\n",
            total_bits, total_bits / 8.0 / 1024.0 / 1024.0);
    return 0;
}
