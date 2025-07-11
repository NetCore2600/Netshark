#ifndef NETSHARK_BPF_H
#define NETSHARK_BPF_H

// Définition minimale pour compilation
#define BPF_MEMWORDS 16

struct bpf_insn {
    unsigned short code;
    unsigned char jt;
    unsigned char jf;
    unsigned int k;
};

struct bpf_program {
    unsigned int bf_len;
    struct bpf_insn *bf_insns;
};

typedef unsigned int bpf_u_int32;

#endif /* NETSHARK_BPF_H */ 