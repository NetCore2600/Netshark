#include "netshark.h"
#include "ethernet.h"

/* ---------------------------------------------------------------------- */
int parse_ethernet_header(
    const unsigned char *frame,
    size_t              frame_len,
    eth_header               *out
) {
    if (!frame || !out)                return -1;
    if (frame_len < ETH_MIN_FRAME)     return -1;   /* not enough for header */

    const ether_info *eh = (const ether_info *)(const void *)frame;

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
    return (int)ETH_MIN_FRAME;                       /* offset to next layer */
}
