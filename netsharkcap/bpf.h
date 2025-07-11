#ifndef BPF_H
#define BPF_H

// Définition minimale pour compilation
struct bpf_insn {
    unsigned short code;
    unsigned char jt;
    unsigned char jf;
    unsigned int k;
};

#endif /* BPF_H */ 