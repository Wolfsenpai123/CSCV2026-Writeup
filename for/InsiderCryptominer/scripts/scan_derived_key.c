/* Challenge-specific 8-byte-stride search for Keplr's derived-key tail.
 * A 128-bit prefix is a fast filter; verify the full MAC and decrypt afterwards.
 */
#include <openssl/sha.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2 || argc > 4) {
        fprintf(stderr, "Usage: %s mem.raw [start] [end]\n", argv[0]);
        return 1;
    }
    int fd = open(argv[1], O_RDONLY);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0) {
        perror("open/stat");
        if (fd >= 0) close(fd);
        return 1;
    }
    size_t start = argc > 2 ? strtoull(argv[2], NULL, 0) : 16;
    size_t end = argc > 3 ? strtoull(argv[3], NULL, 0) : (size_t)st.st_size;
    if (start < 16) start = 16; /* Printing a full key needs the preceding half. */
    if (st.st_size <= 0 || start > end || end > (size_t)st.st_size) {
        fprintf(stderr, "Invalid scan range or empty input\n");
        close(fd);
        return 1;
    }
    unsigned char *memory = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (memory == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 1;
    }
    const unsigned char tail[16] = {
        0xdf, 0xd3, 0xd3, 0x10, 0xd4, 0x9c, 0xe9, 0xb8,
        0xd5, 0x0a, 0xb5, 0x6b, 0x23, 0x46, 0x08, 0x01
    };
    /* SHA-256 padding for a 32-byte message, bit length = 256. */
    unsigned char block[64] = {0};
    memcpy(block + 16, tail, 16);
    block[32] = 0x80;
    block[62] = 1;
    SHA256_CTX initial, candidate;
    SHA256_Init(&initial);
    size_t scanned = 0;
    for (size_t offset = start; end - offset >= 16; offset += 8) {
        memcpy(block, memory + offset, 16);
        candidate = initial;
        SHA256_Transform(&candidate, block);
        scanned++;
        if (candidate.h[0] == 0x43f46daa && candidate.h[1] == 0x1b4b46d5 &&
            candidate.h[2] == 0xc3012639 && candidate.h[3] == 0x84af1473) {
            printf("MATCH tail offset 0x%zx; full key offset 0x%zx: ", offset, offset - 16);
            for (size_t i = offset - 16; i < offset + 16; i++)
                printf("%02x", memory[i]);
            putchar('\n');
        }
    }
    printf("Scanned %zu candidates in [0x%zx, 0x%zx)\n", scanned, start, end);
    munmap(memory, st.st_size);
    close(fd);
    return 0;
}
