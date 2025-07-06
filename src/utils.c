#include "netshark.h"

void dump_hex_single_line(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        printf("%02X", buf[i]);         /* two‑digit hex, no spaces */
}
