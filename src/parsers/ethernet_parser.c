#include "netshark.h"
#include "ethernet.h"

/* helper: format MAC as colon‑separated string */
static void mac_to_str(const uint8_t mac[6], char *dst, size_t dstframe_len)
{
    snprintf(dst, dstframe_len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ---------------------------------------------------------------------- */
int parse_ethernet_frame(
    const unsigned char *frame,
    size_t              frame_len,
    ether               *out
) {
    if (!frame || !out)                return -1;
    if (frame_len < ETH_MIN_FRAME)     return -1;   /* not enough for header */

    const ether_header *eh = (const ether_header *)(const void *)frame;

    memset(out, 0, sizeof *out);
    mac_to_str(eh->dst, out->dst_mac, sizeof out->dst_mac);
    mac_to_str(eh->src, out->src_mac, sizeof out->src_mac);

    /* ---- EtherType or frame_length? ---------------------------------------- */
    uint16_t et = ntohs(eh->type_len);

    size_t offset = sizeof *eh;

    /* VLAN tagging check (single tag only) ----------------------------- */
    if (et == ETHERTYPE_VLAN || et == ETHERTYPE_QINQ) {
        if (frame_len < offset + sizeof(vlan_tag))
            return -1;            /* truncated tag */

        const vlan_tag *tag = (const vlan_tag *)(const void *)(frame + offset);

        out->has_vlan  = 1;
        out->vlan_tpid = et;      /* 0x8100 or 0x88A8                 */

        uint16_t tci   = ntohs(tag->tci);
        out->vlan_pcp  = (uint8_t)((tci >> 13) & 0x07);
        out->vlan_vid  = (uint16_t)(tci & 0x0FFF);

        /* inner EtherType is after the tag */
        offset += sizeof *tag;
        if (frame_len < offset + 2) return -1;

        et = ntohs(*(const uint16_t *)(const void *)(frame + offset));
        offset += 2;
    }

    out->ethertype = et;
    return (int)offset;                       /* offset to next layer */
}
