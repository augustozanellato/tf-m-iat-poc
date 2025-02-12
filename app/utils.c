#include "utils.h"

static const char* alphabet = "0123456789abcdef";

void print_buf_hex(const char* message, const uint8_t* buf, size_t len) {
  printf("%s (%d):", message, len);
  for (size_t i = 0; i < len; i++) {
    if ((i & 0x1F) == 0) {
      putchar('\n');
      putchar('\t');
    }
    uint8_t b = buf[i];
    putchar(alphabet[b >> 4]);
    putchar(alphabet[b & 0xf]);
    putchar(' ');
  }
  putchar('\n');
}