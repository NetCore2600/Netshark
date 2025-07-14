#include "netshark.h"

void dump_hex_single_line(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        printf("%02X", buf[i]);         /* two‑digit hex, no spaces */
}

/* helper: format MAC as colon‑separated string */
void mac_to_str(const uint8_t mac[6], char *dst, size_t dstframe_len)
{
    snprintf(dst, dstframe_len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}
