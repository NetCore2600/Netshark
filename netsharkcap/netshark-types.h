/*
 * Copyright (c) 2002 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2009 CACE Technologies, Inc. Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef NETSHARK_TYPES_H
#define NETSHARK_TYPES_H

/*
 * Get u_int defined, by hook or by crook.
 */
#ifdef _WIN32
  /*
   * This defines u_int.
   */
  #include <winsock2.h>
#else /* _WIN32 */
  /*
   * This defines u_int, among other types.
   */
  #include <sys/types.h>
#endif

// Définitions minimales des DLT nécessaires à la capture Ethernet/IP/WiFi
#ifndef DLT_NULL
#define DLT_NULL 0
#endif
#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif
#ifndef DLT_IEEE802_11
#define DLT_IEEE802_11 105
#endif
#ifndef DLT_RAW
#define DLT_RAW 12
#endif
#ifndef DLT_LOOP
#define DLT_LOOP 108
#endif
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif
#ifndef DLT_DOCSIS
#define DLT_DOCSIS 143
#endif

// Définitions BPF nécessaires à la compilation de grammar.c
#ifndef BPF_JGT
#define BPF_JGT 0x20
#endif
#ifndef BPF_JGE
#define BPF_JGE 0x30
#endif
#ifndef BPF_JEQ
#define BPF_JEQ 0x10
#endif
#ifndef BPF_ADD
#define BPF_ADD 0x00
#endif
#ifndef BPF_SUB
#define BPF_SUB 0x10
#endif
#ifndef BPF_MUL
#define BPF_MUL 0x20
#endif
#ifndef BPF_DIV
#define BPF_DIV 0x30
#endif
#ifndef BPF_MOD
#define BPF_MOD 0x90
#endif
#ifndef BPF_AND
#define BPF_AND 0x50
#endif
#ifndef BPF_OR
#define BPF_OR 0x40
#endif
#ifndef BPF_XOR
#define BPF_XOR 0xa0
#endif
#ifndef BPF_LSH
#define BPF_LSH 0x60
#endif
#ifndef BPF_RSH
#define BPF_RSH 0x70
#endif

#endif // NETSHARK_TYPES_H
