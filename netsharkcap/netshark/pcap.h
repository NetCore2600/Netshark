/* -*- Mode: c; tab-width: 8; indent-tabs-mode: 1; c-basic-offset: 8; -*- */
/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the Computer Systems
 *	Engineering Group at Lawrence Berkeley Laboratory.
 * 4. Neither the name of the University nor of the Laboratory may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Remote packet capture mechanisms and extensions from WinPcap:
 *
 * Copyright (c) 2002 - 2003
 * NetGroup, Politecnico di Torino (Italy)
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
 *
 */

#ifndef lib_netshark_netshark_h
#define lib_netshark_netshark_h

/*
 * Some software that uses libnetshark/WinPcap/Nnetshark defines _MSC_VER before
 * including netshark.h if it's not defined - and it defines it to 1500.
 * (I'm looking at *you*, lwIP!)
 *
 * Attempt to detect this, and undefine _MSC_VER so that we can *reliably*
 * use it to know what compiler is being used and, if it's Visual Studio,
 * what version is being used.
 */
#if defined(_MSC_VER)
  /*
   * We assume here that software such as that doesn't define _MSC_FULL_VER
   * as well and that it defines _MSC_VER with a value > 1200.
   *
   * DO NOT BREAK THESE ASSUMPTIONS.  IF YOU FEEL YOU MUST DEFINE _MSC_VER
   * WITH A COMPILER THAT'S NOT MICROSOFT'S C COMPILER, PLEASE CONTACT
   * US SO THAT WE CAN MAKE IT SO THAT YOU DON'T HAVE TO DO THAT.  THANK
   * YOU.
   *
   * OK, is _MSC_FULL_VER defined?
   */
  #if !defined(_MSC_FULL_VER)
    /*
     * According to
     *
     *    https://sourceforge.net/p/predef/wiki/Compilers/
     *
     * with "Visual C++ 6.0 Processor Pack"/Visual C++ 6.0 SP6 and
     * later, _MSC_FULL_VER is defined, so either this is an older
     * version of Visual C++ or it's not Visual C++ at all.
     *
     * For Visual C++ 6.0, _MSC_VER is defined as 1200.
     */
    #if _MSC_VER > 1200
      /*
       * If this is Visual C++, _MSC_FULL_VER should be defined, so we
       * assume this isn't Visual C++, and undo the lie that it is.
       */
      #undef _MSC_VER
    #endif
  #endif
#endif

#include <netshark/funcattrs.h>

#include <netshark/netshark-inttypes.h>

#if defined(_WIN32)
  #include <winsock2.h>		/* u_int, u_char etc. */
  #include <io.h>		/* _get_osfhandle() */
#else /* UN*X */
  #include <sys/types.h>	/* u_int, u_char etc. */
  #include <sys/time.h>
#endif /* _WIN32/UN*X */

#include <netshark/socket.h>	/* for NETSHARK_SOCKET, as the active-mode rnetshark APIs use it */

#ifndef NETSHARK_DONT_INCLUDE_NETSHARK_BPF_H
#include <netshark/bpf.h>
#endif

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Version number of the current version of the netshark file format.
 *
 * NOTE: this is *NOT* the version number of the libnetshark library.
 * To fetch the version information for the version of libnetshark
 * you're using, use netshark_lib_version().
 */
#define NETSHARK_VERSION_MAJOR 2
#define NETSHARK_VERSION_MINOR 4

#define NETSHARK_ERRBUF_SIZE 256

/*
 * Compatibility for systems that have a bpf.h that
 * predates the bpf typedefs for 64-bit support.
 */
#if ! defined(BPF_RELEASE) || BPF_RELEASE < 199406
typedef	int bpf_int32;
typedef	u_int bpf_u_int32;
#endif

typedef struct netshark netshark_t;
typedef struct netshark_dumper netshark_dumper_t;
typedef struct netshark_if netshark_if_t;
typedef struct netshark_addr netshark_addr_t;

/*
 * The first record in the file contains saved values for some
 * of the flags used in the printout phases of tcpdump.
 * Many fields here are 32 bit ints so compilers won't insert unwanted
 * padding; these files need to be interchangeable across architectures.
 * Documentation: https://www.tcpdump.org/manpages/netshark-savefile.5.txt.
 *
 * Do not change the layout of this structure, in any way (this includes
 * changes that only affect the length of fields in this structure).
 *
 * Also, do not change the interpretation of any of the members of this
 * structure, in any way (this includes using values other than
 * LINKTYPE_ values, as defined in "savefile.c", in the "linktype"
 * field).
 *
 * Instead:
 *
 *	introduce a new structure for the new format, if the layout
 *	of the structure changed;
 *
 *	send mail to "tcpdump-workers@lists.tcpdump.org", requesting
 *	a new magic number for your new capture file format, and, when
 *	you get the new magic number, put it in "savefile.c";
 *
 *	use that magic number for save files with the changed file
 *	header;
 *
 *	make the code in "savefile.c" capable of reading files with
 *	the old file header as well as files with the new file header
 *	(using the magic number to determine the header format).
 *
 * Then supply the changes by forking the branch at
 *
 *	https://github.com/the-tcpdump-group/libnetshark/tree/master
 *
 * and issuing a pull request, so that future versions of libnetshark and
 * programs that use it (such as tcpdump) will be able to read your new
 * capture file format.
 */
struct netshark_file_header {
	bpf_u_int32 magic;
	u_short version_major;
	u_short version_minor;
	bpf_int32 thiszone;	/* not used - SHOULD be filled with 0 */
	bpf_u_int32 sigfigs;	/* not used - SHOULD be filled with 0 */
	bpf_u_int32 snaplen;	/* max length saved portion of each pkt */
	bpf_u_int32 linktype;	/* data link type (LINKTYPE_*) */
};

/*
 * Subfields of the field containing the link-layer header type.
 *
 * Link-layer header types are assigned for both netshark and
 * netsharkng, and the same value must work with both.  In netsharkng,
 * the link-layer header type field in an Interface Description
 * Block is 16 bits, so only the bottommost 16 bits of the
 * link-layer header type in a netshark file can be used for the
 * header type value.
 *
 * In libnetshark, the upper 16 bits, from the top down, are divided into:
 *
 *    A 4-bit "FCS length" field, to allow the FCS length to
 *    be specified, just as it can be specified in the if_fcslen
 *    field of the netsharkng IDB.  The field is in units of 16 bits,
 *    i.e. 1 means 16 bits of FCS, 2 means 32 bits of FCS, etc..
 *
 *    A reserved bit, which must be zero.
 *
 *    An "FCS length present" flag; if 0, the "FCS length" field
 *    should be ignored, and if 1, the "FCS length" field should
 *    be used.
 *
 *    10 reserved bits, which must be zero.  They were originally
 *    intended to be used as a "class" field, allowing additional
 *    classes of link-layer types to be defined, with a class value
 *    of 0 indicating that the link-layer type is a LINKTYPE_ value.
 *    A value of 0x224 was, at one point, used by NetBSD to define
 *    "raw" packet types, with the lower 16 bits containing a
 *    NetBSD AF_ value; see
 *
 *        https://marc.info/?l=tcpdump-workers&m=98296750229149&w=2
 *
 *    It's unknown whether those were ever used in capture files,
 *    or if the intent was just to use it as a link-layer type
 *    for BPF programs; NetBSD's libnetshark used to support them in
 *    the BPF code generator, but it no longer does so.  If it
 *    was ever used in capture files, or if classes other than
 *    "LINKTYPE_ value" are ever useful in capture files, we could
 *    re-enable this, and use the reserved 16 bits following the
 *    link-layer type in netsharkng files to hold the class information
 *    there.  (Note, BTW, that LINKTYPE_RAW/DLT_RAW is now being
 *    interpreted by libnetshark, tcpdump, and Wireshark as "raw IP",
 *    including both IPv4 and IPv6, with the version number in the
 *    header being checked to see which it is, not just "raw IPv4";
 *    there are LINKTYPE_IPV4/DLT_IPV4 and LINKTYPE_IPV6/DLT_IPV6
 *    values if "these are IPv{4,6} and only IPv{4,6} packets"
 *    types are needed.)
 *
 *    Or we might be able to use it for other purposes.
 */
#define LT_LINKTYPE(x)			((x) & 0x0000FFFF)
#define LT_LINKTYPE_EXT(x)		((x) & 0xFFFF0000)
#define LT_RESERVED1(x)			((x) & 0x03FF0000)
#define LT_FCS_LENGTH_PRESENT(x)	((x) & 0x04000000)
#define LT_FCS_LENGTH(x)		(((x) & 0xF0000000) >> 28)
#define LT_FCS_DATALINK_EXT(x)		((((x) & 0xF) << 28) | 0x04000000)

typedef enum {
       NETSHARK_D_INOUT = 0,
       NETSHARK_D_IN,
       NETSHARK_D_OUT
} netshark_direction_t;

/*
 * Generic per-packet information, as supplied by libnetshark.
 *
 * The time stamp can and should be a "struct timeval", regardless of
 * whether your system supports 32-bit tv_sec in "struct timeval",
 * 64-bit tv_sec in "struct timeval", or both if it supports both 32-bit
 * and 64-bit applications.  The on-disk format of savefiles uses 32-bit
 * tv_sec (and tv_usec); this structure is irrelevant to that.  32-bit
 * and 64-bit versions of libnetshark, even if they're on the same platform,
 * should supply the appropriate version of "struct timeval", even if
 * that's not what the underlying packet capture mechanism supplies.
 *
 * caplen is the number of packet bytes available in the packet.
 *
 * len is the number of bytes that would have been available if
 * the capture process had not discarded data at the end of the
 * packet, either because a snapshot length less than the packet
 * size was provided or because the mechanism used to capture
 * the packet imposed a limit on the amount of packet data
 * that is provided.
 */
struct netshark_pkthdr {
	struct timeval ts;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present in data */
	bpf_u_int32 len;	/* length of this packet prior to any slicing */
};

/*
 * As returned by the netshark_stats()
 */
struct netshark_stat {
	u_int ps_recv;		/* number of packets received */
	u_int ps_drop;		/* number of packets dropped */
	u_int ps_ifdrop;	/* drops by interface -- only supported on some platforms */
#ifdef _WIN32
	u_int ps_capt;		/* number of packets that reach the application */
	u_int ps_sent;		/* number of packets sent by the server on the network */
	u_int ps_netdrop;	/* number of packets lost on the network */
#endif /* _WIN32 */
};

/*
 * Item in a list of interfaces.
 */
struct netshark_if {
	struct netshark_if *next;
	char *name;		/* name to hand to "netshark_open_live()" */
	char *description;	/* textual description of interface, or NULL */
	struct netshark_addr *addresses;
	bpf_u_int32 flags;	/* NETSHARK_IF_ interface flags */
};

#define NETSHARK_IF_LOOPBACK				0x00000001	/* interface is loopback */
#define NETSHARK_IF_UP					0x00000002	/* interface is up */
#define NETSHARK_IF_RUNNING					0x00000004	/* interface is running */
#define NETSHARK_IF_WIRELESS				0x00000008	/* interface is wireless (*NOT* necessarily Wi-Fi!) */
#define NETSHARK_IF_CONNECTION_STATUS			0x00000030	/* connection status: */
#define NETSHARK_IF_CONNECTION_STATUS_UNKNOWN		0x00000000	/* unknown */
#define NETSHARK_IF_CONNECTION_STATUS_CONNECTED		0x00000010	/* connected */
#define NETSHARK_IF_CONNECTION_STATUS_DISCONNECTED		0x00000020	/* disconnected */
#define NETSHARK_IF_CONNECTION_STATUS_NOT_APPLICABLE	0x00000030	/* not applicable */

/*
 * Representation of an interface address.
 */
struct netshark_addr {
	struct netshark_addr *next;
	struct sockaddr *addr;		/* address */
	struct sockaddr *netmask;	/* netmask for that address */
	struct sockaddr *broadaddr;	/* broadcast address for that address */
	struct sockaddr *dstaddr;	/* P2P destination address for that address */
};

typedef void (*netshark_handler)(u_char *, const struct netshark_pkthdr *,
			     const u_char *);

/*
 * Error codes for the netshark API.
 * These will all be negative, so you can check for the success or
 * failure of a call that returns these codes by checking for a
 * negative value.
 */
#define NETSHARK_ERROR			-1	/* generic error code */
#define NETSHARK_ERROR_BREAK		-2	/* loop terminated by netshark_breakloop */
#define NETSHARK_ERROR_NOT_ACTIVATED	-3	/* the capture needs to be activated */
#define NETSHARK_ERROR_ACTIVATED		-4	/* the operation can't be performed on already activated captures */
#define NETSHARK_ERROR_NO_SUCH_DEVICE	-5	/* no such device exists */
#define NETSHARK_ERROR_RFMON_NOTSUP		-6	/* this device doesn't support rfmon (monitor) mode */
#define NETSHARK_ERROR_NOT_RFMON		-7	/* operation supported only in monitor mode */
#define NETSHARK_ERROR_PERM_DENIED		-8	/* no permission to open the device */
#define NETSHARK_ERROR_IFACE_NOT_UP		-9	/* interface isn't up */
#define NETSHARK_ERROR_CANTSET_TSTAMP_TYPE	-10	/* this device doesn't support setting the time stamp type */
#define NETSHARK_ERROR_PROMISC_PERM_DENIED	-11	/* you don't have permission to capture in promiscuous mode */
#define NETSHARK_ERROR_TSTAMP_PRECISION_NOTSUP -12  /* the requested time stamp precision is not supported */
#define NETSHARK_ERROR_CAPTURE_NOTSUP	-13	/* capture mechanism not available */

/*
 * Warning codes for the netshark API.
 * These will all be positive and non-zero, so they won't look like
 * errors.
 */
#define NETSHARK_WARNING			1	/* generic warning code */
#define NETSHARK_WARNING_PROMISC_NOTSUP	2	/* this device doesn't support promiscuous mode */
#define NETSHARK_WARNING_TSTAMP_TYPE_NOTSUP	3	/* the requested time stamp type is not supported */

/*
 * Value to pass to netshark_compile() as the netmask if you don't know what
 * the netmask is.
 */
#define NETSHARK_NETMASK_UNKNOWN	0xffffffff

/*
 * Initialize netshark.  If this isn't called, netshark is initialized to
 * a mode source-compatible and binary-compatible with older versions
 * that lack this routine.
 */

/*
 * Initialization options.
 * All bits not listed here are reserved for expansion.
 *
 * On UNIX-like systems, the local character encoding is assumed to be
 * UTF-8, so no character encoding transformations are done.
 *
 * On Windows, the local character encoding is the local ANSI code page.
 */
#define NETSHARK_CHAR_ENC_LOCAL	0x00000000U	/* strings are in the local character encoding */
#define NETSHARK_CHAR_ENC_UTF_8	0x00000001U	/* strings are in UTF-8 */
#define NETSHARK_MMAP_32BIT	0x00000002U	/* map packet buffers with 32-bit addresses */

NETSHARK_AVAILABLE_1_10
NETSHARK_API int	netshark_init(unsigned int, char *)
	    NETSHARK_NONNULL(2) NETSHARK_WARN_UNUSED_RESULT;

/*
 * We're deprecating netshark_lookupdev() for various reasons (not
 * thread-safe, can behave weirdly with WinPcap).  Callers
 * should use netshark_findalldevs() and use the first device.
 */
NETSHARK_AVAILABLE_0_4
NETSHARK_DEPRECATED("use 'netshark_findalldevs' and use the first device")
NETSHARK_API char	*netshark_lookupdev(char *);

NETSHARK_AVAILABLE_0_4
NETSHARK_API int	netshark_lookupnet(const char *, bpf_u_int32 *, bpf_u_int32 *,
	    char *) NETSHARK_NONNULL(4) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_1_0
NETSHARK_API netshark_t	*netshark_create(const char *, char *) NETSHARK_NONNULL(2);

NETSHARK_AVAILABLE_1_0
NETSHARK_API int	netshark_set_snaplen(netshark_t *, int) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_1_0
NETSHARK_API int	netshark_set_promisc(netshark_t *, int) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_1_0
NETSHARK_API int	netshark_can_set_rfmon(netshark_t *);

NETSHARK_AVAILABLE_1_0
NETSHARK_API int	netshark_set_rfmon(netshark_t *, int) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_1_0
NETSHARK_API int	netshark_set_timeout(netshark_t *, int) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_1_2
NETSHARK_API int	netshark_set_tstamp_type(netshark_t *, int) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_1_5
NETSHARK_API int	netshark_set_immediate_mode(netshark_t *, int) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_1_0
NETSHARK_API int	netshark_set_buffer_size(netshark_t *, int) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_1_5
NETSHARK_API int	netshark_set_tstamp_precision(netshark_t *, int)
	    NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_1_5
NETSHARK_API int	netshark_get_tstamp_precision(netshark_t *) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_1_0
NETSHARK_API int	netshark_activate(netshark_t *) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_1_2
NETSHARK_API int	netshark_list_tstamp_types(netshark_t *, int **);

NETSHARK_AVAILABLE_1_2
NETSHARK_API void	netshark_free_tstamp_types(int *);

NETSHARK_AVAILABLE_1_2
NETSHARK_API int	netshark_tstamp_type_name_to_val(const char *);

NETSHARK_AVAILABLE_1_2
NETSHARK_API const char *netshark_tstamp_type_val_to_name(int);

NETSHARK_AVAILABLE_1_2
NETSHARK_API const char *netshark_tstamp_type_val_to_description(int);

#ifdef __linux__
NETSHARK_AVAILABLE_1_9
NETSHARK_API int	netshark_set_protocol_linux(netshark_t *, int) NETSHARK_WARN_UNUSED_RESULT;
#endif

/*
 * Time stamp types.
 * Not all systems and interfaces will necessarily support all of these.
 *
 * A system that supports NETSHARK_TSTAMP_HOST is offering time stamps
 * provided by the host machine, rather than by the capture device,
 * but not committing to any characteristics of the time stamp.
 *
 * NETSHARK_TSTAMP_HOST_LOWPREC is a time stamp, provided by the host machine,
 * that's low-precision but relatively cheap to fetch; it's normally done
 * using the system clock, so it's normally synchronized with times you'd
 * fetch from system calls.
 *
 * NETSHARK_TSTAMP_HOST_HIPREC is a time stamp, provided by the host machine,
 * that's high-precision; it might be more expensive to fetch.  It is
 * synchronized with the system clock.
 *
 * NETSHARK_TSTAMP_HOST_HIPREC_UNSYNCED is a time stamp, provided by the host
 * machine, that's high-precision; it might be more expensive to fetch.
 * It is not synchronized with the system clock, and might have
 * problems with time stamps for packets received on different CPUs,
 * depending on the platform.  It might be more likely to be strictly
 * monotonic than NETSHARK_TSTAMP_HOST_HIPREC.
 *
 * NETSHARK_TSTAMP_ADAPTER is a high-precision time stamp supplied by the
 * capture device; it's synchronized with the system clock.
 *
 * NETSHARK_TSTAMP_ADAPTER_UNSYNCED is a high-precision time stamp supplied by
 * the capture device; it's not synchronized with the system clock.
 *
 * Note that time stamps synchronized with the system clock can go
 * backwards, as the system clock can go backwards.  If a clock is
 * not in sync with the system clock, that could be because the
 * system clock isn't keeping accurate time, because the other
 * clock isn't keeping accurate time, or both.
 *
 * Note that host-provided time stamps generally correspond to the
 * time when the time-stamping code sees the packet; this could
 * be some unknown amount of time after the first or last bit of
 * the packet is received by the network adapter, due to batching
 * of interrupts for packet arrival, queueing delays, etc..
 */
#define NETSHARK_TSTAMP_HOST			0	/* host-provided, unknown characteristics */
#define NETSHARK_TSTAMP_HOST_LOWPREC		1	/* host-provided, low precision, synced with the system clock */
#define NETSHARK_TSTAMP_HOST_HIPREC			2	/* host-provided, high precision, synced with the system clock */
#define NETSHARK_TSTAMP_ADAPTER			3	/* device-provided, synced with the system clock */
#define NETSHARK_TSTAMP_ADAPTER_UNSYNCED		4	/* device-provided, not synced with the system clock */
#define NETSHARK_TSTAMP_HOST_HIPREC_UNSYNCED	5	/* host-provided, high precision, not synced with the system clock */

/*
 * Time stamp resolution types.
 * Not all systems and interfaces will necessarily support all of these
 * resolutions when doing live captures; all of them can be requested
 * when reading a savefile.
 */
#define NETSHARK_TSTAMP_PRECISION_MICRO	0	/* use timestamps with microsecond precision, default */
#define NETSHARK_TSTAMP_PRECISION_NANO	1	/* use timestamps with nanosecond precision */

NETSHARK_AVAILABLE_0_4
NETSHARK_API netshark_t	*netshark_open_live(const char *, int, int, int, char *)
	    NETSHARK_NONNULL(5);

NETSHARK_AVAILABLE_0_6
NETSHARK_API netshark_t	*netshark_open_dead(int, int);

NETSHARK_AVAILABLE_1_5
NETSHARK_API netshark_t	*netshark_open_dead_with_tstamp_precision(int, int, u_int);

NETSHARK_AVAILABLE_1_5
NETSHARK_API netshark_t	*netshark_open_offline_with_tstamp_precision(const char *, u_int,
	    char *) NETSHARK_NONNULL(3);

NETSHARK_AVAILABLE_0_4
NETSHARK_API netshark_t	*netshark_open_offline(const char *, char *) NETSHARK_NONNULL(2);

#ifdef _WIN32
  NETSHARK_AVAILABLE_1_5
  NETSHARK_API netshark_t  *netshark_hopen_offline_with_tstamp_precision(intptr_t, u_int,
	    char *) NETSHARK_NONNULL(3);

  NETSHARK_API netshark_t  *netshark_hopen_offline(intptr_t, char *) NETSHARK_NONNULL(2);
  /*
   * If we're building libnetshark, these are internal routines in savefile.c,
   * so we must not define them as macros.
   *
   * If we're not building libnetshark, given that the version of the C runtime
   * with which libnetshark was built might be different from the version
   * of the C runtime with which an application using libnetshark was built,
   * and that a FILE structure may differ between the two versions of the
   * C runtime, calls to _fileno() must use the version of _fileno() in
   * the C runtime used to open the FILE *, not the version in the C
   * runtime with which libnetshark was built.  (Maybe once the Universal CRT
   * rules the world, this will cease to be a problem.)
   */
  #ifndef BUILDING_NETSHARK
    #define netshark_fopen_offline_with_tstamp_precision(f,p,b) \
	netshark_hopen_offline_with_tstamp_precision(_get_osfhandle(_fileno(f)), p, b)
    #define netshark_fopen_offline(f,b) \
	netshark_hopen_offline(_get_osfhandle(_fileno(f)), b)
  #endif
#else /*_WIN32*/
  NETSHARK_AVAILABLE_1_5
  NETSHARK_API netshark_t	*netshark_fopen_offline_with_tstamp_precision(FILE *,
	    u_int, char *) NETSHARK_NONNULL(3);

  NETSHARK_AVAILABLE_0_9
  NETSHARK_API netshark_t	*netshark_fopen_offline(FILE *, char *) NETSHARK_NONNULL(2);
#endif /*_WIN32*/

NETSHARK_AVAILABLE_0_4
NETSHARK_API void	netshark_close(netshark_t *);

NETSHARK_AVAILABLE_0_4
NETSHARK_API int	netshark_loop(netshark_t *, int, netshark_handler, u_char *)
	    NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_0_4
NETSHARK_API int	netshark_dispatch(netshark_t *, int, netshark_handler, u_char *)
	    NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_0_4
NETSHARK_API const u_char *netshark_next(netshark_t *, struct netshark_pkthdr *);

NETSHARK_AVAILABLE_0_8
NETSHARK_API int	netshark_next_ex(netshark_t *, struct netshark_pkthdr **, const u_char **);

NETSHARK_AVAILABLE_0_8
NETSHARK_API void	netshark_breakloop(netshark_t *);

NETSHARK_AVAILABLE_0_4
NETSHARK_API int	netshark_stats(netshark_t *, struct netshark_stat *)
	    NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_0_4
NETSHARK_API int	netshark_setfilter(netshark_t *, struct bpf_program *)
	     NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_0_9
NETSHARK_API int	netshark_setdirection(netshark_t *, netshark_direction_t)
	     NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_0_7
NETSHARK_API int	netshark_getnonblock(netshark_t *, char *);

NETSHARK_AVAILABLE_0_7
NETSHARK_API int	netshark_setnonblock(netshark_t *, int, char *)
	     NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_0_9
NETSHARK_API int	netshark_inject(netshark_t *, const void *, size_t)
	    NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_0_8
NETSHARK_API int	netshark_sendpacket(netshark_t *, const u_char *, int)
	    NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_1_0
NETSHARK_API const char *netshark_statustostr(int);

NETSHARK_AVAILABLE_0_4
NETSHARK_API const char *netshark_strerror(int);

NETSHARK_AVAILABLE_0_4
NETSHARK_API char	*netshark_geterr(netshark_t *);

NETSHARK_AVAILABLE_0_4
NETSHARK_API void	netshark_perror(netshark_t *, const char *);

NETSHARK_AVAILABLE_0_4
NETSHARK_API int	netshark_compile(netshark_t *, struct bpf_program *, const char *, int,
	    bpf_u_int32) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_0_5
NETSHARK_DEPRECATED("use netshark_open_dead(), netshark_compile() and netshark_close()")
NETSHARK_API int	netshark_compile_nonetshark(int, int, struct bpf_program *,
	    const char *, int, bpf_u_int32) NETSHARK_WARN_UNUSED_RESULT;

/* XXX - this took two arguments in 0.4 and 0.5 */
NETSHARK_AVAILABLE_0_6
NETSHARK_API void	netshark_freecode(struct bpf_program *);

NETSHARK_AVAILABLE_1_0
NETSHARK_API int	netshark_offline_filter(const struct bpf_program *,
	    const struct netshark_pkthdr *, const u_char *);

NETSHARK_AVAILABLE_0_4
NETSHARK_API int	netshark_datalink(netshark_t *);

NETSHARK_AVAILABLE_1_0
NETSHARK_API int	netshark_datalink_ext(netshark_t *);

NETSHARK_AVAILABLE_0_8
NETSHARK_API int	netshark_list_datalinks(netshark_t *, int **);

NETSHARK_AVAILABLE_0_8
NETSHARK_API int	netshark_set_datalink(netshark_t *, int) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_0_8
NETSHARK_API void	netshark_free_datalinks(int *);

NETSHARK_AVAILABLE_0_8
NETSHARK_API int	netshark_datalink_name_to_val(const char *);

NETSHARK_AVAILABLE_0_8
NETSHARK_API const char *netshark_datalink_val_to_name(int);

NETSHARK_AVAILABLE_0_8
NETSHARK_API const char *netshark_datalink_val_to_description(int);

NETSHARK_AVAILABLE_1_9
NETSHARK_API const char *netshark_datalink_val_to_description_or_dlt(int);

NETSHARK_AVAILABLE_0_4
NETSHARK_API int	netshark_snapshot(netshark_t *);

NETSHARK_AVAILABLE_0_4
NETSHARK_API int	netshark_is_swapped(netshark_t *);

NETSHARK_AVAILABLE_0_4
NETSHARK_API int	netshark_major_version(netshark_t *);

NETSHARK_AVAILABLE_0_4
NETSHARK_API int	netshark_minor_version(netshark_t *);

NETSHARK_AVAILABLE_1_9
NETSHARK_API int	netshark_bufsize(netshark_t *);

/* XXX */
NETSHARK_AVAILABLE_0_4
NETSHARK_API FILE	*netshark_file(netshark_t *);

#ifdef _WIN32
/*
 * This probably shouldn't have been kept in WinPcap; most if not all
 * UN*X code that used it won't work on Windows.  We deprecate it; if
 * anybody really needs access to whatever HANDLE may be associated
 * with a netshark_t (there's no guarantee that there is one), we can add
 * a Windows-only netshark_handle() API that returns the HANDLE.
 */
NETSHARK_AVAILABLE_0_4
NETSHARK_DEPRECATED("request a 'netshark_handle' that returns a HANDLE if you need it")
NETSHARK_API int	netshark_fileno(netshark_t *);
#else /* _WIN32 */
NETSHARK_AVAILABLE_0_4
NETSHARK_API int	netshark_fileno(netshark_t *);
#endif /* _WIN32 */

#ifdef _WIN32
  NETSHARK_API int	netshark_wsockinit(void);
#endif

NETSHARK_AVAILABLE_0_4
NETSHARK_API netshark_dumper_t *netshark_dump_open(netshark_t *, const char *);

#ifdef _WIN32
  NETSHARK_AVAILABLE_0_9
  NETSHARK_API netshark_dumper_t *netshark_dump_hopen(netshark_t *, intptr_t);

  /*
   * If we're building libnetshark, this is an internal routine in sf-netshark.c, so
   * we must not define it as a macro.
   *
   * If we're not building libnetshark, given that the version of the C runtime
   * with which libnetshark was built might be different from the version
   * of the C runtime with which an application using libnetshark was built,
   * and that a FILE structure may differ between the two versions of the
   * C runtime, calls to _fileno() must use the version of _fileno() in
   * the C runtime used to open the FILE *, not the version in the C
   * runtime with which libnetshark was built.  (Maybe once the Universal CRT
   * rules the world, this will cease to be a problem.)
   */
  #ifndef BUILDING_NETSHARK
    #define netshark_dump_fopen(p,f) \
	netshark_dump_hopen(p, _get_osfhandle(_fileno(f)))
  #endif
#else /*_WIN32*/
  NETSHARK_AVAILABLE_0_9
  NETSHARK_API netshark_dumper_t *netshark_dump_fopen(netshark_t *, FILE *fp);
#endif /*_WIN32*/

NETSHARK_AVAILABLE_1_7
NETSHARK_API netshark_dumper_t *netshark_dump_open_append(netshark_t *, const char *);

NETSHARK_AVAILABLE_0_8
NETSHARK_API FILE	*netshark_dump_file(netshark_dumper_t *);

NETSHARK_AVAILABLE_0_9
NETSHARK_API long	netshark_dump_ftell(netshark_dumper_t *);

NETSHARK_AVAILABLE_1_9
NETSHARK_API int64_t	netshark_dump_ftell64(netshark_dumper_t *);

NETSHARK_AVAILABLE_0_8
NETSHARK_API int	netshark_dump_flush(netshark_dumper_t *);

NETSHARK_AVAILABLE_0_4
NETSHARK_API void	netshark_dump_close(netshark_dumper_t *);

NETSHARK_AVAILABLE_0_4
NETSHARK_API void	netshark_dump(u_char *, const struct netshark_pkthdr *, const u_char *);

NETSHARK_AVAILABLE_0_7
NETSHARK_API int	netshark_findalldevs(netshark_if_t **, char *)
	    NETSHARK_NONNULL(2) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_0_7
NETSHARK_API void	netshark_freealldevs(netshark_if_t *);

/*
 * We return a pointer to the version string, rather than exporting the
 * version string directly.
 *
 * On at least some UNIXes, if you import data from a shared library into
 * a program, the data is bound into the program binary, so if the string
 * in the version of the library with which the program was linked isn't
 * the same as the string in the version of the library with which the
 * program is being run, various undesirable things may happen (warnings,
 * the string being the one from the version of the library with which the
 * program was linked, or even weirder things, such as the string being the
 * one from the library but being truncated).
 *
 * On Windows, the string is constructed at run time.
 */
NETSHARK_AVAILABLE_0_8
NETSHARK_API const char *netshark_lib_version(void);

#if defined(_WIN32)

  /*
   * Win32 definitions
   */

  /*!
    \brief A queue of raw packets that will be sent to the network with netshark_sendqueue_transmit().
  */
  struct netshark_send_queue
  {
	u_int maxlen;	/* Maximum size of the queue, in bytes. This
			   variable contains the size of the buffer field. */
	u_int len;	/* Current size of the queue, in bytes. */
	char *buffer;	/* Buffer containing the packets to be sent. */
  };

  typedef struct netshark_send_queue netshark_send_queue;

  /*!
    \brief This typedef is a support for the netshark_get_airnetshark_handle() function
*/
#if !defined(AIRNETSHARK_HANDLE__EAE405F5_0171_9592_B3C2_C19EC426AD34__DEFINED_)
	#define AIRNETSHARK_HANDLE__EAE405F5_0171_9592_B3C2_C19EC426AD34__DEFINED_
	  typedef struct _AirnetsharkHandle* PAirnetsharkHandle;
#endif

  NETSHARK_API int netshark_setbuff(netshark_t *p, int dim) NETSHARK_WARN_UNUSED_RESULT;
  NETSHARK_API int netshark_setmode(netshark_t *p, int mode) NETSHARK_WARN_UNUSED_RESULT;
  NETSHARK_API int netshark_setmintocopy(netshark_t *p, int size) NETSHARK_WARN_UNUSED_RESULT;

  NETSHARK_API HANDLE netshark_getevent(netshark_t *p);

  NETSHARK_AVAILABLE_1_8
  NETSHARK_API int netshark_oid_get_request(netshark_t *, bpf_u_int32, void *, size_t *)
	     NETSHARK_WARN_UNUSED_RESULT;

  NETSHARK_AVAILABLE_1_8
  NETSHARK_API int netshark_oid_set_request(netshark_t *, bpf_u_int32, const void *,
	    size_t *) NETSHARK_WARN_UNUSED_RESULT;

  NETSHARK_API netshark_send_queue* netshark_sendqueue_alloc(u_int memsize);

  NETSHARK_API void netshark_sendqueue_destroy(netshark_send_queue* queue);

  NETSHARK_API int netshark_sendqueue_queue(netshark_send_queue* queue, const struct netshark_pkthdr *pkt_header, const u_char *pkt_data);

  NETSHARK_API u_int netshark_sendqueue_transmit(netshark_t *p, netshark_send_queue* queue, int sync);

  NETSHARK_API struct netshark_stat *netshark_stats_ex(netshark_t *p, int *netshark_stat_size);

  NETSHARK_API int netshark_setuserbuffer(netshark_t *p, int size) NETSHARK_WARN_UNUSED_RESULT;

  NETSHARK_API int netshark_live_dump(netshark_t *p, char *filename, int maxsize,
	    int maxpacks) NETSHARK_WARN_UNUSED_RESULT;

  NETSHARK_API int netshark_live_dump_ended(netshark_t *p, int sync)
	    NETSHARK_WARN_UNUSED_RESULT;

  NETSHARK_API int netshark_start_oem(char* err_str, int flags);

  NETSHARK_DEPRECATED("AirPcap support has been removed")
  NETSHARK_API PAirnetsharkHandle netshark_get_airnetshark_handle(netshark_t* p);

  #define MODE_CAPT 0
  #define MODE_STAT 1
  #define MODE_MON 2

#else /* UN*X */

  /*
   * UN*X definitions
   */

  NETSHARK_AVAILABLE_0_8
  NETSHARK_API int	netshark_get_selectable_fd(netshark_t *);

  NETSHARK_AVAILABLE_1_9
  NETSHARK_API const struct timeval *netshark_get_required_select_timeout(netshark_t *);

#endif /* _WIN32/UN*X */

/*
 * APIs added in WinPcap for remote capture.
 *
 * They are present even if remote capture isn't enabled, as they
 * also support local capture, and as their absence may complicate
 * code build on macOS 14 with Xcode 15, as that platform supports
 * "weakly linked symbols":
 *
 *    https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFrameworks/Concepts/WeakLinking.html
 *
 * which are symbols in dynamically-linked shared libraries, declared in
 * such a fashion that if a program linked against a newer software
 * development kit (SDK), and using a symbol present in the OS version
 * for which that SDK is provided, is run on an older OS version that
 * lacks that symbol, that symbol's value is a NULL pointer.  This
 * allows those programs to test for the presence of that symbol
 * by checking whether it's non-null and, if it is, using the symbol,
 * otherwise not using it.
 *
 * (This is a slightly more convenient alternative to the usual
 * technique used on Windows - and also available, and sometimes
 * used, on UN*Xes - of loading the library containing the symbol
 * at run time with dlopen() on UN*Xes and LoadLibrary() on Windows,
 * looking up the symbol with dlsym() on UN*Xes and GetProcAddress()
 * on Windows, and using the symbol with the returned pointer if it's
 * not null.)
 */

/*
 * The maximum buffer size in which address, port, interface names are kept.
 *
 * In case the adapter name or such is larger than this value, it is truncated.
 * This is not used by the user; however it must be aware that an hostname / interface
 * name longer than this value will be truncated.
 */
#define NETSHARK_BUF_SIZE 1024

/*
 * The type of input source, passed to netshark_open().
 */
#define NETSHARK_SRC_FILE		2	/* local savefile */
#define NETSHARK_SRC_IFLOCAL	3	/* local network interface */
#define NETSHARK_SRC_IFREMOTE	4	/* interface on a remote host, using RNETSHARK */

/*
 * The formats allowed by netshark_open() are the following (optional parts in []):
 * - file://path_and_filename [opens a local file]
 * - rnetshark://devicename [opens the selected device available on the local host, without using the RNETSHARK protocol]
 * - rnetshark://[username:password@]host[:port]/devicename [opens the selected device available on a remote host]
 *   - username and password, if present, will be used to authenticate to the remote host
 *   - port, if present, will specify a port for RNETSHARK rather than using the default
 * - adaptername [to open a local adapter; kept for compatibility, but it is strongly discouraged]
 * - (NULL) [to open the first local adapter; kept for compatibility, but it is strongly discouraged]
 *
 * The formats allowed by the netshark_findalldevs_ex() are the following (optional parts in []):
 * - file://folder/ [lists all the files in the given folder]
 * - rnetshark:// [lists all local adapters]
 * - rnetshark://[username:password@]host[:port]/ [lists the devices available on a remote host]
 *   - username and password, if present, will be used to authenticate to the remote host
 *   - port, if present, will specify a port for RNETSHARK rather than using the default
 *
 * In all the above, "rnetsharks://" can be substituted for "rnetshark://" to enable
 * SSL (if it has been compiled in).
 *
 * Referring to the 'host' and 'port' parameters, they can be either numeric or literal. Since
 * IPv6 is fully supported, these are the allowed formats:
 *
 * - host (literal): e.g. host.foo.bar
 * - host (numeric IPv4): e.g. 10.11.12.13
 * - host (numeric IPv4, IPv6 style): e.g. [10.11.12.13]
 * - host (numeric IPv6): e.g. [1:2:3::4]
 * - port: can be either numeric (e.g. '80') or literal (e.g. 'http')
 *
 * Here you find some allowed examples:
 * - rnetshark://host.foo.bar/devicename [everything literal, no port number]
 * - rnetshark://host.foo.bar:1234/devicename [everything literal, with port number]
 * - rnetshark://root:hunter2@host.foo.bar/devicename [everything literal, with username/password]
 * - rnetshark://10.11.12.13/devicename [IPv4 numeric, no port number]
 * - rnetshark://10.11.12.13:1234/devicename [IPv4 numeric, with port number]
 * - rnetshark://[10.11.12.13]:1234/devicename [IPv4 numeric with IPv6 format, with port number]
 * - rnetshark://[1:2:3::4]/devicename [IPv6 numeric, no port number]
 * - rnetshark://[1:2:3::4]:1234/devicename [IPv6 numeric, with port number]
 * - rnetshark://[1:2:3::4]:http/devicename [IPv6 numeric, with literal port number]
 */

/*
 * URL schemes for capture source.
 */
/*
 * This string indicates that the user wants to open a capture from a
 * local file.
 */
#define NETSHARK_SRC_FILE_STRING "file://"
/*
 * This string indicates that the user wants to open a capture from a
 * network interface.  This string does not necessarily involve the use
 * of the RNETSHARK protocol. If the interface required resides on the local
 * host, the RNETSHARK protocol is not involved and the local functions are used.
 */
#define NETSHARK_SRC_IF_STRING "rnetshark://"

/*
 * Flags to pass to netshark_open().
 */

/*
 * Specifies whether promiscuous mode is to be used.
 */
#define NETSHARK_OPENFLAG_PROMISCUOUS		0x00000001

/*
 * Specifies, for an RNETSHARK capture, whether the data transfer (in
 * case of a remote capture) has to be done with UDP protocol.
 *
 * If it is '1' if you want a UDP data connection, '0' if you want
 * a TCP data connection; control connection is always TCP-based.
 * A UDP connection is much lighter, but it does not guarantee that all
 * the captured packets arrive to the client workstation. Moreover,
 * it could be harmful in case of network congestion.
 * This flag is meaningless if the source is not a remote interface.
 * In that case, it is simply ignored.
 */
#define NETSHARK_OPENFLAG_DATATX_UDP		0x00000002

/*
 * Specifies whether the remote probe will capture its own generated
 * traffic.
 *
 * In case the remote probe uses the same interface to capture traffic
 * and to send data back to the caller, the captured traffic includes
 * the RNETSHARK traffic as well.  If this flag is turned on, the RNETSHARK
 * traffic is excluded from the capture, so that the trace returned
 * back to the collector is does not include this traffic.
 *
 * Has no effect on local interfaces or savefiles.
 */
#define NETSHARK_OPENFLAG_NOCAPTURE_RNETSHARK		0x00000004

/*
 * Specifies whether the local adapter will capture its own generated traffic.
 *
 * This flag tells the underlying capture driver to drop the packets
 * that were sent by itself.  This is useful when building applications
 * such as bridges that should ignore the traffic they just sent.
 *
 * Supported only on Windows.
 */
#define NETSHARK_OPENFLAG_NOCAPTURE_LOCAL		0x00000008

/*
 * This flag configures the adapter for maximum responsiveness.
 *
 * In presence of a large value for nbytes, WinPcap waits for the arrival
 * of several packets before copying the data to the user. This guarantees
 * a low number of system calls, i.e. lower processor usage, i.e. better
 * performance, which is good for applications like sniffers. If the user
 * sets the NETSHARK_OPENFLAG_MAX_RESPONSIVENESS flag, the capture driver will
 * copy the packets as soon as the application is ready to receive them.
 * This is suggested for real time applications (such as, for example,
 * a bridge) that need the best responsiveness.
 *
 * The equivalent with netshark_create()/netshark_activate() is "immediate mode".
 */
#define NETSHARK_OPENFLAG_MAX_RESPONSIVENESS	0x00000010

/*
 * Remote authentication methods.
 * These are used in the 'type' member of the netshark_rmtauth structure.
 */

/*
 * NULL authentication.
 *
 * The 'NULL' authentication has to be equal to 'zero', so that old
 * applications can just put every field of struct netshark_rmtauth to zero,
 * and it does work.
 */
#define RNETSHARK_RMTAUTH_NULL 0
/*
 * Username/password authentication.
 *
 * With this type of authentication, the RNETSHARK protocol will use the username/
 * password provided to authenticate the user on the remote machine. If the
 * authentication is successful (and the user has the right to open network
 * devices) the RNETSHARK connection will continue; otherwise it will be dropped.
 *
 * *******NOTE********: unless TLS is being used, the username and password
 * are sent over the network to the capture server *IN CLEAR TEXT*.  Don't
 * use this, without TLS (i.e., with rnetshark:// rather than rnetsharks://) on
 * a network that you don't completely control!  (And be *really* careful
 * in your definition of "completely"!)
 */
#define RNETSHARK_RMTAUTH_PWD 1

/*
 * This structure keeps the information needed to authenticate the user
 * on a remote machine.
 *
 * The remote machine can either grant or refuse the access according
 * to the information provided.
 * In case the NULL authentication is required, both 'username' and
 * 'password' can be NULL pointers.
 *
 * This structure is meaningless if the source is not a remote interface;
 * in that case, the functions which requires such a structure can accept
 * a NULL pointer as well.
 */
struct netshark_rmtauth
{
	/*
	 * \brief Type of the authentication required.
	 *
	 * In order to provide maximum flexibility, we can support different types
	 * of authentication based on the value of this 'type' variable. The currently
	 * supported authentication methods are defined into the
	 * \link remote_auth_methods Remote Authentication Methods Section\endlink.
	 */
	int type;
	/*
	 * \brief Zero-terminated string containing the username that has to be
	 * used on the remote machine for authentication.
	 *
	 * This field is meaningless in case of the RNETSHARK_RMTAUTH_NULL authentication
	 * and it can be NULL.
	 */
	char *username;
	/*
	 * \brief Zero-terminated string containing the password that has to be
	 * used on the remote machine for authentication.
	 *
	 * This field is meaningless in case of the RNETSHARK_RMTAUTH_NULL authentication
	 * and it can be NULL.
	 */
	char *password;
};

/*
 * This routine can open a savefile, a local device, or a device on
 * a remote machine running an RNETSHARK server.
 *
 * For opening a savefile, the netshark_open_offline routines can be used,
 * and will work just as well; code using them will work on more
 * platforms than code using netshark_open() to open savefiles.
 *
 * For opening a local device, netshark_open_live() can be used; it supports
 * most of the capabilities that netshark_open() supports, and code using it
 * will work on more platforms than code using netshark_open().  netshark_create()
 * and netshark_activate() can also be used; they support all capabilities
 * that netshark_open() supports, except for the Windows-only
 * NETSHARK_OPENFLAG_NOCAPTURE_LOCAL, and support additional capabilities.
 *
 * For opening a remote capture, netshark_open() is currently the only
 * API available.
 */
NETSHARK_AVAILABLE_1_9_REMOTE
NETSHARK_API netshark_t	*netshark_open(const char *source, int snaplen, int flags,
	    int read_timeout, struct netshark_rmtauth *auth, char *errbuf)
	    NETSHARK_NONNULL(6);

NETSHARK_AVAILABLE_1_9_REMOTE
NETSHARK_API int	netshark_createsrcstr(char *source, int type, const char *host,
	    const char *port, const char *name, char *errbuf)
	    NETSHARK_NONNULL(6) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_1_9_REMOTE
NETSHARK_API int	netshark_parsesrcstr(const char *source, int *type, char *host,
	    char *port, char *name, char *errbuf)
	    NETSHARK_NONNULL(6) NETSHARK_WARN_UNUSED_RESULT;

/*
 * This routine can scan a directory for savefiles, list local capture
 * devices, or list capture devices on a remote machine running an RNETSHARK
 * server.
 *
 * For scanning for savefiles, it can be used on both UN*X systems and
 * Windows systems; for each directory entry it sees, it tries to open
 * the file as a savefile using netshark_open_offline(), and only includes
 * it in the list of files if the open succeeds, so it filters out
 * files for which the user doesn't have read permission, as well as
 * files that aren't valid savefiles readable by libnetshark.
 *
 * For listing local capture devices, it's just a wrapper around
 * netshark_findalldevs(); code using netshark_findalldevs() will work on more
 * platforms than code using netshark_findalldevs_ex().
 *
 * For listing remote capture devices, netshark_findalldevs_ex() is currently
 * the only API available.
 */
NETSHARK_AVAILABLE_1_9_REMOTE
NETSHARK_API int	netshark_findalldevs_ex(const char *source,
	    struct netshark_rmtauth *auth, netshark_if_t **alldevs, char *errbuf)
	    NETSHARK_NONNULL(4) NETSHARK_WARN_UNUSED_RESULT;

/*
 * Sampling methods.
 *
 * These allow netshark_loop(), netshark_dispatch(), netshark_next(), and netshark_next_ex()
 * to see only a sample of packets, rather than all packets.
 *
 * Currently, they work only on Windows local captures.
 */

/*
 * Specifies that no sampling is to be done on the current capture.
 *
 * In this case, no sampling algorithms are applied to the current capture.
 */
#define NETSHARK_SAMP_NOSAMP	0

/*
 * Specifies that only 1 out of N packets must be returned to the user.
 *
 * In this case, the 'value' field of the 'netshark_samp' structure indicates the
 * number of packets (minus 1) that must be discarded before one packet got
 * accepted.
 * In other words, if 'value = 10', the first packet is returned to the
 * caller, while the following 9 are discarded.
 */
#define NETSHARK_SAMP_1_EVERY_N	1

/*
 * Specifies that we have to return 1 packet every N milliseconds.
 *
 * In this case, the 'value' field of the 'netshark_samp' structure indicates
 * the 'waiting time' in milliseconds before one packet got accepted.
 * In other words, if 'value = 10', the first packet is returned to the
 * caller; the next returned one will be the first packet that arrives
 * when 10ms have elapsed.
 */
#define NETSHARK_SAMP_FIRST_AFTER_N_MS 2

/*
 * This structure defines the information related to sampling.
 *
 * In case the sampling is requested, the capturing device should read
 * only a subset of the packets coming from the source. The returned packets
 * depend on the sampling parameters.
 *
 * WARNING: The sampling process is applied *after* the filtering process.
 * In other words, packets are filtered first, then the sampling process
 * selects a subset of the 'filtered' packets and it returns them to the
 * caller.
 */
struct netshark_samp
{
	/*
	 * Method used for sampling; see above.
	 */
	int method;

	/*
	 * This value depends on the sampling method defined.
	 * For its meaning, see above.
	 */
	int value;
};

/*
 * New functions.
 */
NETSHARK_AVAILABLE_1_9_REMOTE
NETSHARK_API struct netshark_samp *netshark_setsampling(netshark_t *p);

/*
 * RNETSHARK active mode.
 */

/* Maximum length of an host name (needed for the RNETSHARK active mode) */
#define RNETSHARK_HOSTLIST_SIZE 1024

NETSHARK_AVAILABLE_1_9_REMOTE
NETSHARK_API NETSHARK_SOCKET	netshark_remoteact_accept(const char *address,
	    const char *port, const char *hostlist, char *connectinghost,
	    struct netshark_rmtauth *auth, char *errbuf)
	    NETSHARK_NONNULL(6);

NETSHARK_AVAILABLE_1_10_REMOTE
NETSHARK_API NETSHARK_SOCKET	netshark_remoteact_accept_ex(const char *address,
	    const char *port, const char *hostlist, char *connectinghost,
	    struct netshark_rmtauth *auth, int uses_ssl, char *errbuf)
	    NETSHARK_NONNULL(7);

NETSHARK_AVAILABLE_1_9_REMOTE
NETSHARK_API int	netshark_remoteact_list(char *hostlist, char sep, int size,
	    char *errbuf) NETSHARK_NONNULL(4) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_1_9_REMOTE
NETSHARK_API int	netshark_remoteact_close(const char *host, char *errbuf)
	    NETSHARK_NONNULL(2) NETSHARK_WARN_UNUSED_RESULT;

NETSHARK_AVAILABLE_1_9_REMOTE
NETSHARK_API void	netshark_remoteact_cleanup(void);

enum netshark_option_name {  /* never renumber this */
		       PON_TSTAMP_PRECISION = 1,  /* int */
		       PON_IO_READ_PLUGIN   = 2,  /* char * */
		       PON_IO_WRITE_PLUGIN  = 3,  /* char * */
};
typedef struct netshark_options netshark_options;
NETSHARK_AVAILABLE_1_11
NETSHARK_API netshark_options *netshark_alloc_option(void);

NETSHARK_AVAILABLE_1_11
NETSHARK_API void netshark_free_option(netshark_options *po);

NETSHARK_AVAILABLE_1_11
NETSHARK_API int netshark_set_option_string(netshark_options *po,
				    enum netshark_option_name pon, const char *value);

NETSHARK_AVAILABLE_1_11
NETSHARK_API int netshark_set_option_int(netshark_options *po,
				 enum netshark_option_name pon, const int value);

NETSHARK_AVAILABLE_1_11
NETSHARK_API const char *netshark_get_option_string(netshark_options *po, enum netshark_option_name pon);

NETSHARK_AVAILABLE_1_11
NETSHARK_API int netshark_get_option_int(netshark_options *po, enum netshark_option_name pon);

#ifdef __cplusplus
}
#endif

#endif /* lib_netshark_netshark_h */
