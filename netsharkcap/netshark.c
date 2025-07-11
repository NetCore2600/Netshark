/*
 * Copyright (c) 1993, 1994, 1995, 1996, 1997, 1998
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

#include <config.h>

/*
 * Include this before including any system header files, as it
 * may do some #defines that cause those headers to declare
 * more functions than they do by default.
 */
#include "ftmacros.h"

#include <netshark-types.h>
#ifndef _WIN32
#include <sys/param.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

/*
 * On most supported platforms <sys/ioctl.h> also defines the SIOCGIF* macros.
 * However, on Haiku, illumos and Solaris the macros need <sys/sockio.h>,
 * which does not exist in AIX 7, HP-UX 11, GNU/Hurd and Linux (both GNU and
 * musl libc).
 */
#if defined(HAVE_SOLARIS) || defined(__HAIKU__)
#include <sys/sockio.h>
#endif

#include <net/if.h>
#include <netinet/in.h>
#endif /* _WIN32 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_MSC_VER) && !defined(__BORLANDC__) && !defined(__MINGW32__)
#include <unistd.h>
#endif
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include "diag-control.h"

#include "thread-local.h"

#ifdef HAVE_OS_PROTO_H
#include "os-proto.h"
#endif

#include "netshark-int.h"

#include "optimize.h"

// Support pour Linux uniquement - autres plateformes supprimées

#ifdef _WIN32
/*
 * To quote the WSAStartup() documentation:
 *
 *   The WSAStartup function typically leads to protocol-specific helper
 *   DLLs being loaded. As a result, the WSAStartup function should not
 *   be called from the DllMain function in a application DLL. This can
 *   potentially cause deadlocks.
 *
 * and the WSACleanup() documentation:
 *
 *   The WSACleanup function typically leads to protocol-specific helper
 *   DLLs being unloaded. As a result, the WSACleanup function should not
 *   be called from the DllMain function in a application DLL. This can
 *   potentially cause deadlocks.
 *
 * So we don't initialize Winsock in a DllMain() routine.
 *
 * Similarly, we cannot register an atexit() handler to call WSACleanup()
 * because that handler will be run in the context of DllMain. Therefore, we
 * call WSAStartup each time Winsock is needed and WSACleanup as soon as it is
 * no longer needed.
 */

/*
 * Shut down Winsock.
 *
 * Ignores the return value of WSACleanup(); given that this is
 * an atexit() routine, there's nothing much we can do about
 * a failure.
 */
static void
internal_wsockfini(void)
{
	WSACleanup();
}

/*
 * Start Winsock.
 * Internal routine.
 */
static int
internal_wsockinit(char *errbuf)
{
	return 0;
}

/*
 * Exported in case some applications using WinPcap/Nnetshark called it,
 * even though it wasn't exported.
 */
int
wsockinit(void)
{
	return (internal_wsockinit(NULL));
}

/*
 * This is the exported function; new programs should call this.
 * *Newer* programs should call netshark_init().
 */
int
netshark_wsockinit(void)
{
	return (internal_wsockinit(NULL));
}
#endif /* _WIN32 */

/*
 * Do whatever initialization is needed for libnetshark.
 *
 * The argument specifies whether we use the local code page or UTF-8
 * for strings; on UN*X, we just assume UTF-8 in places where the encoding
 * would matter, whereas, on Windows, we use the local code page for
 * NETSHARK_CHAR_ENC_LOCAL and UTF-8 for NETSHARK_CHAR_ENC_UTF_8.
 *
 * On Windows, we also disable the hack in netshark_create() to deal with
 * being handed UTF-16 strings, because if the user calls this they're
 * explicitly declaring that they will either be passing local code
 * page strings or UTF-8 strings, so we don't need to allow UTF-16LE
 * strings to be passed.  For good measure, on Windows *and* UN*X,
 * we disable netshark_lookupdev(), to prevent anybody from even
 * *trying* to pass the result of netshark_lookupdev() - which might be
 * UTF-16LE on Windows, for ugly compatibility reasons - to netshark_create()
 * or netshark_open_live() or netshark_open().
 *
 * Returns 0 on success, -1 on error.
 */
int netsharkint_new_api;		/* netshark_lookupdev() always fails */
int netsharkint_utf_8_mode;		/* Strings should be in UTF-8. */
int netsharkint_mmap_32bit;		/* Map packet buffers with 32-bit addresses. */

int
netshark_init(unsigned int opts, char *errbuf)
{
	static int initialized;

	/*
	 * Don't allow multiple calls that set different modes; that
	 * may mean a library is initializing netshark in one mode and
	 * a program using that library, or another library used by
	 * that program, is initializing it in another mode.
	 */
	switch (opts) {

	case NETSHARK_CHAR_ENC_LOCAL:
		/* Leave "UTF-8 mode" off. */
		if (initialized) {
			if (netsharkint_utf_8_mode) {
				snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
				    "Multiple netshark_init calls with different character encodings");
				return (NETSHARK_ERROR);
			}
		}
		break;

	case NETSHARK_CHAR_ENC_UTF_8:
		/* Turn on "UTF-8 mode". */
		if (initialized) {
			if (!netsharkint_utf_8_mode) {
				snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
				    "Multiple netshark_init calls with different character encodings");
				return (NETSHARK_ERROR);
			}
		}
		netsharkint_utf_8_mode = 1;
		break;

	case NETSHARK_MMAP_32BIT:
		netsharkint_mmap_32bit = 1;
		break;

	default:
		snprintf(errbuf, NETSHARK_ERRBUF_SIZE, "Unknown options specified");
		return (NETSHARK_ERROR);
	}

	/*
	 * Turn the appropriate mode on for error messages; those routines
	 * are also used in rnetsharkd, which has no access to netshark's internal
	 * UTF-8 mode flag, so we have to call a routine to set its
	 * UTF-8 mode flag.
	 */
	netsharkint_fmt_set_encoding(opts);

	if (initialized) {
		/*
		 * Nothing more to do; for example, on Windows, we've
		 * already initialized Winsock.
		 */
		return (0);
	}

	/*
	 * We're done.
	 */
	initialized = 1;
	netsharkint_new_api = 1;
	return (0);
}

/*
 * String containing the library version.
 * Not explicitly exported via a header file - the right API to use
 * is netshark_lib_version() - but some programs included it, so we
 * provide it.
 *
 * We declare it here, right before defining it, to squelch any
 * warnings we might get from compilers about the lack of a
 * declaration.
 */
NETSHARK_API char netshark_version[];
NETSHARK_API_DEF char netshark_version[] = PACKAGE_VERSION;

static void
netshark_set_not_initialized_message(netshark_t *netshark)
{
	if (netshark->activated) {
		/* A module probably forgot to set the function pointer */
		(void)snprintf(netshark->errbuf, sizeof(netshark->errbuf),
		    "This operation isn't properly handled by that device");
		return;
	}
	/* in case the caller doesn't check for NETSHARK_ERROR_NOT_ACTIVATED */
	(void)snprintf(netshark->errbuf, sizeof(netshark->errbuf),
	    "This handle hasn't been activated yet");
}

static int
netshark_read_not_initialized(netshark_t *netshark, int cnt _U_, netshark_handler callback _U_,
    u_char *user _U_)
{
	netshark_set_not_initialized_message(netshark);
	/* this means 'not initialized' */
	return (NETSHARK_ERROR_NOT_ACTIVATED);
}

static int
netshark_inject_not_initialized(netshark_t *netshark, const void * buf _U_, int size _U_)
{
	netshark_set_not_initialized_message(netshark);
	/* this means 'not initialized' */
	return (NETSHARK_ERROR_NOT_ACTIVATED);
}

static int
netshark_setfilter_not_initialized(netshark_t *netshark, struct bpf_program *fp _U_)
{
	netshark_set_not_initialized_message(netshark);
	/* this means 'not initialized' */
	return (NETSHARK_ERROR_NOT_ACTIVATED);
}

static int
netshark_setdirection_not_initialized(netshark_t *netshark, netshark_direction_t d _U_)
{
	netshark_set_not_initialized_message(netshark);
	/* this means 'not initialized' */
	return (NETSHARK_ERROR_NOT_ACTIVATED);
}

static int
netshark_set_datalink_not_initialized(netshark_t *netshark, int dlt _U_)
{
	netshark_set_not_initialized_message(netshark);
	/* this means 'not initialized' */
	return (NETSHARK_ERROR_NOT_ACTIVATED);
}

static int
netshark_getnonblock_not_initialized(netshark_t *netshark)
{
	netshark_set_not_initialized_message(netshark);
	/* this means 'not initialized' */
	return (NETSHARK_ERROR_NOT_ACTIVATED);
}

static int
netshark_stats_not_initialized(netshark_t *netshark, struct netshark_stat *ps _U_)
{
	netshark_set_not_initialized_message(netshark);
	/* this means 'not initialized' */
	return (NETSHARK_ERROR_NOT_ACTIVATED);
}

#ifdef _WIN32
static struct netshark_stat *
netshark_stats_ex_not_initialized(netshark_t *netshark, int *netshark_stat_size _U_)
{
	netshark_set_not_initialized_message(netshark);
	return (NULL);
}

static int
netshark_setbuff_not_initialized(netshark_t *netshark, int dim _U_)
{
	netshark_set_not_initialized_message(netshark);
	/* this means 'not initialized' */
	return (NETSHARK_ERROR_NOT_ACTIVATED);
}

static int
netshark_setmode_not_initialized(netshark_t *netshark, int mode _U_)
{
	netshark_set_not_initialized_message(netshark);
	/* this means 'not initialized' */
	return (NETSHARK_ERROR_NOT_ACTIVATED);
}

static int
netshark_setmintocopy_not_initialized(netshark_t *netshark, int size _U_)
{
	netshark_set_not_initialized_message(netshark);
	/* this means 'not initialized' */
	return (NETSHARK_ERROR_NOT_ACTIVATED);
}

static HANDLE
netshark_getevent_not_initialized(netshark_t *netshark)
{
	netshark_set_not_initialized_message(netshark);
	return (INVALID_HANDLE_VALUE);
}

static int
netshark_oid_get_request_not_initialized(netshark_t *netshark, bpf_u_int32 oid _U_,
    void *data _U_, size_t *lenp _U_)
{
	netshark_set_not_initialized_message(netshark);
	return (NETSHARK_ERROR_NOT_ACTIVATED);
}

static int
netshark_oid_set_request_not_initialized(netshark_t *netshark, bpf_u_int32 oid _U_,
    const void *data _U_, size_t *lenp _U_)
{
	netshark_set_not_initialized_message(netshark);
	return (NETSHARK_ERROR_NOT_ACTIVATED);
}

static u_int
netshark_sendqueue_transmit_not_initialized(netshark_t *netshark, netshark_send_queue* queue _U_,
    int sync _U_)
{
	netshark_set_not_initialized_message(netshark);
	return (0);
}

static int
netshark_setuserbuffer_not_initialized(netshark_t *netshark, int size _U_)
{
	netshark_set_not_initialized_message(netshark);
	return (NETSHARK_ERROR_NOT_ACTIVATED);
}

static int
netshark_live_dump_not_initialized(netshark_t *netshark, char *filename _U_, int maxsize _U_,
    int maxpacks _U_)
{
	netshark_set_not_initialized_message(netshark);
	return (NETSHARK_ERROR_NOT_ACTIVATED);
}

static int
netshark_live_dump_ended_not_initialized(netshark_t *netshark, int sync _U_)
{
	netshark_set_not_initialized_message(netshark);
	return (NETSHARK_ERROR_NOT_ACTIVATED);
}
#endif

/*
 * Returns 1 if rfmon mode can be set on the netshark_t, 0 if it can't,
 * a NETSHARK_ERROR value on an error.
 */
int
netshark_can_set_rfmon(netshark_t *p)
{
	return (p->can_set_rfmon_op(p));
}

/*
 * For systems where rfmon mode is never supported.
 */
static int
netshark_cant_set_rfmon(netshark_t *p _U_)
{
	return (0);
}

/*
 * Sets *tstamp_typesp to point to an array 1 or more supported time stamp
 * types; the return value is the number of supported time stamp types.
 * The list should be freed by a call to netshark_free_tstamp_types() when
 * you're done with it.
 *
 * A return value of 0 means "you don't get a choice of time stamp type",
 * in which case *tstamp_typesp is set to null.
 *
 * NETSHARK_ERROR is returned on error.
 */
int
netshark_list_tstamp_types(netshark_t *p, int **tstamp_typesp)
{
	if (p->tstamp_type_count == 0) {
		/*
		 * We don't support multiple time stamp types.
		 * That means the only type we support is NETSHARK_TSTAMP_HOST;
		 * set up a list containing only that type.
		 */
		*tstamp_typesp = (int*)malloc(sizeof(**tstamp_typesp));
		if (*tstamp_typesp == NULL) {
			netsharkint_fmt_errmsg_for_errno(p->errbuf, sizeof(p->errbuf),
			    errno, "malloc");
			return (NETSHARK_ERROR);
		}
		**tstamp_typesp = NETSHARK_TSTAMP_HOST;
		return (1);
	} else {
		*tstamp_typesp = (int*)calloc(p->tstamp_type_count,
					      sizeof(**tstamp_typesp));
		if (*tstamp_typesp == NULL) {
			netsharkint_fmt_errmsg_for_errno(p->errbuf, sizeof(p->errbuf),
			    errno, "malloc");
			return (NETSHARK_ERROR);
		}
		(void)memcpy(*tstamp_typesp, p->tstamp_type_list,
		    sizeof(**tstamp_typesp) * p->tstamp_type_count);
		return (p->tstamp_type_count);
	}
}

/*
 * In Windows, you might have a library built with one version of the
 * C runtime library and an application built with another version of
 * the C runtime library, which means that the library might use one
 * version of malloc() and free() and the application might use another
 * version of malloc() and free().  If so, that means something
 * allocated by the library cannot be freed by the application, so we
 * need to have a netshark_free_tstamp_types() routine to free up the list
 * allocated by netshark_list_tstamp_types(), even though it's just a wrapper
 * around free().
 */
void
netshark_free_tstamp_types(int *tstamp_type_list)
{
	free(tstamp_type_list);
}

/*
 * Default one-shot callback; overridden for capture types where the
 * packet data cannot be guaranteed to be available after the callback
 * returns, so that a copy must be made.
 */
void
netsharkint_oneshot(u_char *user, const struct netshark_pkthdr *h, const u_char *pkt)
{
	struct oneshot_userdata *sp = (struct oneshot_userdata *)user;

	*sp->hdr = *h;
	*sp->pkt = pkt;
}

const u_char *
netshark_next(netshark_t *p, struct netshark_pkthdr *h)
{
	struct oneshot_userdata s;
	const u_char *pkt;

	s.hdr = h;
	s.pkt = &pkt;
	s.pd = p;
	if (netshark_dispatch(p, 1, p->oneshot_callback, (u_char *)&s) <= 0)
		return (0);
	return (pkt);
}

int
netshark_next_ex(netshark_t *p, struct netshark_pkthdr **pkt_header,
    const u_char **pkt_data)
{
	struct oneshot_userdata s;

	s.hdr = &p->netshark_header;
	s.pkt = pkt_data;
	s.pd = p;

	/* Saves a pointer to the packet headers */
	*pkt_header= &p->netshark_header;

	if (p->rfile != NULL) {
		int status;

		/* We are on an offline capture */
		status = netsharkint_offline_read(p, 1, p->oneshot_callback,
		    (u_char *)&s);

		/*
		 * Return codes for netsharkint_offline_read() are:
		 *   -  0: EOF
		 *   - -1: error
		 *   - >0: OK - result is number of packets read, so
		 *         it will be 1 in this case, as we've passed
		 *         a maximum packet count of 1
		 * The first one ('0') conflicts with the return code of
		 * 0 from netshark_read() meaning "no packets arrived before
		 * the timeout expired", so we map it to -2 so you can
		 * distinguish between an EOF from a savefile and a
		 * "no packets arrived before the timeout expired, try
		 * again" from a live capture.
		 */
		if (status == 0)
			return (-2);
		else
			return (status);
	}

	/*
	 * Return codes for netshark_read() are:
	 *   -  0: timeout
	 *   - -1: error
	 *   - -2: loop was broken out of with netshark_breakloop()
	 *   - >0: OK, result is number of packets captured, so
	 *         it will be 1 in this case, as we've passed
	 *         a maximum packet count of 1
	 * The first one ('0') conflicts with the return code of 0 from
	 * netsharkint_offline_read() meaning "end of file".
	*/
	return (p->read_op(p, 1, p->oneshot_callback, (u_char *)&s));
}

/*
 * Implementation of a netshark_if_list_t.
 */
struct netshark_if_list {
	netshark_if_t *beginning;
};

static struct capture_source_type {
	int (*findalldevs_op)(netshark_if_list_t *, char *);
	netshark_t *(*create_op)(const char *, char *, int *);
} capture_source_types[] = {
	// Support Linux uniquement - autres plateformes supprimées
	{ NULL, NULL }
};

/*
 * Get a list of all capture sources that are up and that we can open.
 * Returns -1 on error, 0 otherwise.
 * The list, as returned through "alldevsp", may be null if no interfaces
 * were up and could be opened.
 */
int
netshark_findalldevs(netshark_if_t **alldevsp, char *errbuf)
{
	size_t i;
	netshark_if_list_t devlist;

	/*
	 * Find all the local network interfaces on which we
	 * can capture.
	 */
	devlist.beginning = NULL;
	if (netsharkint_platform_finddevs(&devlist, errbuf) == -1) {
		/*
		 * Failed - free all of the entries we were given
		 * before we failed.
		 */
		if (devlist.beginning != NULL)
			netshark_freealldevs(devlist.beginning);
		*alldevsp = NULL;
		return (-1);
	}

	/*
	 * Ask each of the non-local-network-interface capture
	 * source types what interfaces they have.
	 */
	for (i = 0; capture_source_types[i].findalldevs_op != NULL; i++) {
		if (capture_source_types[i].findalldevs_op(&devlist, errbuf) == -1) {
			/*
			 * We had an error; free the list we've been
			 * constructing.
			 */
			if (devlist.beginning != NULL)
				netshark_freealldevs(devlist.beginning);
			*alldevsp = NULL;
			return (-1);
		}
	}

	/*
	 * Return the first entry of the list of all devices.
	 */
	*alldevsp = devlist.beginning;
	return (0);
}

static struct sockaddr *
dup_sockaddr(struct sockaddr *sa, size_t sa_length)
{
	struct sockaddr *newsa;

	if ((newsa = malloc(sa_length)) == NULL)
		return (NULL);
	return (memcpy(newsa, sa, sa_length));
}

/*
 * Construct a "figure of merit" for an interface, for use when sorting
 * the list of interfaces, in which interfaces that are up are superior
 * to interfaces that aren't up, interfaces that are up and running are
 * superior to interfaces that are up but not running, and non-loopback
 * interfaces that are up and running are superior to loopback interfaces,
 * and interfaces with the same flags have a figure of merit that's higher
 * the lower the instance number.
 *
 * The goal is to try to put the interfaces most likely to be useful for
 * capture at the beginning of the list.
 *
 * The figure of merit, which is lower the "better" the interface is,
 * has the uppermost bit set if the interface isn't running, the bit
 * below that set if the interface isn't up, the bit below that
 * set if the interface is a loopback interface, and the bit below
 * that set if it's the "any" interface.
 *
 * Note: we don't sort by unit number because 1) not all interfaces have
 * a unit number (systemd, for example, might assign interface names
 * based on the interface's MAC address or on the physical location of
 * the adapter's connector), and 2) if the name does end with a simple
 * unit number, it's not a global property of the interface, it's only
 * useful as a sort key for device names with the same prefix, so xyz0
 * shouldn't necessarily sort before abc2.  This means that interfaces
 * with the same figure of merit will be sorted by the order in which
 * the mechanism from which we're getting the interfaces supplies them.
 */
static u_int
get_figure_of_merit(netshark_if_t *dev)
{
	u_int n;

	n = 0;
	if (!(dev->flags & NETSHARK_IF_RUNNING))
		n |= 0x80000000;
	if (!(dev->flags & NETSHARK_IF_UP))
		n |= 0x40000000;

	/*
	 * Give non-wireless interfaces that aren't disconnected a better
	 * figure of merit than interfaces that are disconnected, as
	 * "disconnected" should indicate that the interface isn't
	 * plugged into a network and thus won't give you any traffic.
	 *
	 * For wireless interfaces, it means "associated with a network",
	 * which we presume not to necessarily prevent capture, as you
	 * might run the adapter in some flavor of monitor mode.
	 */
	if (!(dev->flags & NETSHARK_IF_WIRELESS) &&
	    (dev->flags & NETSHARK_IF_CONNECTION_STATUS) == NETSHARK_IF_CONNECTION_STATUS_DISCONNECTED)
		n |= 0x20000000;

	/*
	 * Sort loopback devices after non-loopback devices, *except* for
	 * disconnected devices.
	 */
	if (dev->flags & NETSHARK_IF_LOOPBACK)
		n |= 0x10000000;

	/*
	 * Sort the "any" device before loopback and disconnected devices,
	 * but after all other devices.
	 */
	if (strcmp(dev->name, "any") == 0)
		n |= 0x08000000;

	return (n);
}

#ifndef _WIN32
/*
 * Try to get a description for a given device.
 * Returns a malloced description if it could and NULL if it couldn't.
 *
 * XXX - on FreeBSDs that support it, should it get the sysctl named
 * "dev.{adapter family name}.{adapter unit}.%desc" to get a description
 * of the adapter?  Note that "dev.an.0.%desc" is "Aironet PC4500/PC4800"
 * with my Cisco 350 card, so the name isn't entirely descriptive.  The
 * "dev.an.0.%pnpinfo" has a better description, although one might argue
 * that the problem is really a driver bug - if it can find out that it's
 * a Cisco 340 or 350, rather than an old Aironet card, it should use
 * that in the description.
 *
 * Do NetBSD, DragonflyBSD, or OpenBSD support this as well?  FreeBSD
 * and OpenBSD let you get a description, but it's not generated by the OS,
 * it's set with another ioctl that ifconfig supports; we use that to get
 * a description in FreeBSD and OpenBSD, but if there is no such
 * description available, it still might be nice to get some description
 * string based on the device type or something such as that.
 *
 * In macOS, the System Configuration framework can apparently return
 * names in 10.4 and later.
 *
 * It also appears that freedesktop.org's HAL offers an "info.product"
 * string, but the HAL specification says it "should not be used in any
 * UI" and "subsystem/capability specific properties" should be used
 * instead and, in any case, I think HAL is being deprecated in
 * favor of other stuff such as DeviceKit.  DeviceKit doesn't appear
 * to have any obvious product information for devices, but maybe
 * I haven't looked hard enough.
 *
 * Using the System Configuration framework, or HAL, or DeviceKit, or
 * whatever, would require that libnetshark applications be linked with
 * the frameworks/libraries in question.  That shouldn't be a problem
 * for programs linking with the shared version of libnetshark (unless
 * you're running on AIX - which I think is the only UN*X that doesn't
 * support linking a shared library with other libraries on which it
 * depends, and having an executable linked only with the first shared
 * library automatically pick up the other libraries when started -
 * and using HAL or whatever).  Programs linked with the static
 * version of libnetshark would have to use netshark-config with the --static
 * flag in order to get the right linker flags in order to pick up
 * the additional libraries/frameworks; those programs need that anyway
 * for libnetshark 1.1 and beyond on Linux, as, by default, it requires
 * -lnl.
 *
 * Do any other UN*Xes, or desktop environments support getting a
 * description?
 */
static char *
#ifdef SIOCGIFDESCR
get_if_description(const char *name)
{
	char *description = NULL;
	int s;
	struct ifreq ifrdesc;
#ifndef IFDESCRSIZE
	size_t descrlen = 64;
#else
	size_t descrlen = IFDESCRSIZE;
#endif /* IFDESCRSIZE */

	/*
	 * Get the description for the interface.
	 */
	memset(&ifrdesc, 0, sizeof ifrdesc);
	netsharkint_strlcpy(ifrdesc.ifr_name, name, sizeof ifrdesc.ifr_name);
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s >= 0) {
#ifdef __FreeBSD__
		/*
		 * On FreeBSD, if the buffer isn't big enough for the
		 * description, the ioctl succeeds, but the description
		 * isn't copied, ifr_buffer.length is set to the description
		 * length, and ifr_buffer.buffer is set to NULL.
		 */
		for (;;) {
			free(description);
			if ((description = malloc(descrlen)) != NULL) {
				ifrdesc.ifr_buffer.buffer = description;
				ifrdesc.ifr_buffer.length = descrlen;
				if (ioctl(s, SIOCGIFDESCR, &ifrdesc) == 0) {
					if (ifrdesc.ifr_buffer.buffer ==
					    description)
						break;
					else
						descrlen = ifrdesc.ifr_buffer.length;
				} else {
					/*
					 * Failed to get interface description.
					 */
					free(description);
					description = NULL;
					break;
				}
			} else
				break;
		}
#else /* __FreeBSD__ */
		/*
		 * The only other OS that currently supports
		 * SIOCGIFDESCR is OpenBSD, and it has no way
		 * to get the description length - it's clamped
		 * to a maximum of IFDESCRSIZE.
		 */
		if ((description = malloc(descrlen)) != NULL) {
			ifrdesc.ifr_data = (caddr_t)description;
			if (ioctl(s, SIOCGIFDESCR, &ifrdesc) != 0) {
				/*
				 * Failed to get interface description.
				 */
				free(description);
				description = NULL;
			}
		}
#endif /* __FreeBSD__ */
		close(s);
		if (description != NULL && description[0] == '\0') {
			/*
			 * Description is empty, so discard it.
			 */
			free(description);
			description = NULL;
		}
	}

#ifdef __FreeBSD__
	/*
	 * For FreeBSD, if we didn't get a description, and this is
	 * a device with a name of the form usbusN, label it as a USB
	 * bus.
	 */
	if (description == NULL) {
		if (strncmp(name, "usbus", 5) == 0) {
			/*
			 * OK, it begins with "usbus".
			 */
			long busnum;
			char *p;

			errno = 0;
			busnum = strtol(name + 5, &p, 10);
			if (errno == 0 && p != name + 5 && *p == '\0' &&
			    busnum >= 0 && busnum <= INT_MAX) {
				/*
				 * OK, it's a valid number that's not
				 * bigger than INT_MAX.  Construct
				 * a description from it.
				 * (If that fails, we don't worry about
				 * it, we just return NULL.)
				 */
				if (netsharkint_asprintf(&description,
				    "USB bus number %ld", busnum) == -1) {
					/* Failed. */
					description = NULL;
				}
			}
		}
	}
#endif
	return (description);
#else /* SIOCGIFDESCR */
get_if_description(const char *name _U_)
{
	return (NULL);
#endif /* SIOCGIFDESCR */
}

/*
 * Look for a given device in the specified list of devices.
 *
 * If we find it, return a pointer to its entry.
 *
 * If we don't find it, attempt to add an entry for it, with the specified
 * IFF_ flags and description, and, if that succeeds, return a pointer to
 * the new entry, otherwise return NULL and set errbuf to an error message.
 */
netshark_if_t *
netsharkint_find_or_add_if(netshark_if_list_t *devlistp, const char *name,
    uint64_t if_flags, get_if_flags_func get_flags_func, char *errbuf)
{
	bpf_u_int32 netshark_flags;

	/*
	 * Convert IFF_ flags to netshark flags.
	 */
	netshark_flags = 0;
#ifdef IFF_LOOPBACK
	if (if_flags & IFF_LOOPBACK)
		netshark_flags |= NETSHARK_IF_LOOPBACK;
#else
	/*
	 * We don't have IFF_LOOPBACK, so look at the device name to
	 * see if it looks like a loopback device.
	 */
	if (name[0] == 'l' && name[1] == 'o' &&
	    (NETSHARK_ISDIGIT(name[2]) || name[2] == '\0'))
		netshark_flags |= NETSHARK_IF_LOOPBACK;
#endif
#ifdef IFF_UP
	if (if_flags & IFF_UP)
		netshark_flags |= NETSHARK_IF_UP;
#endif
#ifdef IFF_RUNNING
	if (if_flags & IFF_RUNNING)
		netshark_flags |= NETSHARK_IF_RUNNING;
#endif

	/*
	 * Attempt to find an entry for this device; if we don't find one,
	 * attempt to add one.
	 */
	return (netsharkint_find_or_add_dev(devlistp, name, netshark_flags,
	    get_flags_func, get_if_description(name), errbuf));
}

/*
 * Look for a given device in the specified list of devices.
 *
 * If we find it, then, if the specified address isn't null, add it to
 * the list of addresses for the device and return 0.
 *
 * If we don't find it, attempt to add an entry for it, with the specified
 * IFF_ flags and description, and, if that succeeds, add the specified
 * address to its list of addresses if that address is non-null, and
 * return 0, otherwise return -1 and set errbuf to an error message.
 *
 * (We can get called with a null address because we might get a list
 * of interface name/address combinations from the underlying OS, with
 * the address being absent in some cases, rather than a list of
 * interfaces with each interface having a list of addresses, so this
 * call may be the only call made to add to the list, and we want to
 * add interfaces even if they have no addresses.)
 */
int
netsharkint_add_addr_to_if(netshark_if_list_t *devlistp, const char *name,
    uint64_t if_flags, get_if_flags_func get_flags_func,
    struct sockaddr *addr, size_t addr_size,
    struct sockaddr *netmask, size_t netmask_size,
    struct sockaddr *broadaddr, size_t broadaddr_size,
    struct sockaddr *dstaddr, size_t dstaddr_size,
    char *errbuf)
{
	netshark_if_t *curdev;

	/*
	 * Check whether the device exists and, if not, add it.
	 */
	curdev = netsharkint_find_or_add_if(devlistp, name, if_flags, get_flags_func,
	    errbuf);
	if (curdev == NULL) {
		/*
		 * Error - give up.
		 */
		return (-1);
	}

	if (addr == NULL) {
		/*
		 * There's no address to add; this entry just meant
		 * "here's a new interface".
		 */
		return (0);
	}

	/*
	 * "curdev" is an entry for this interface, and we have an
	 * address for it; add an entry for that address to the
	 * interface's list of addresses.
	 */
	return (netsharkint_add_addr_to_dev(curdev, addr, addr_size, netmask,
	    netmask_size, broadaddr, broadaddr_size, dstaddr,
	    dstaddr_size, errbuf));
}
#endif /* _WIN32 */

/*
 * Add an entry to the list of addresses for an interface.
 * "curdev" is the entry for that interface.
 */
int
netsharkint_add_addr_to_dev(netshark_if_t *curdev,
    struct sockaddr *addr, size_t addr_size,
    struct sockaddr *netmask, size_t netmask_size,
    struct sockaddr *broadaddr, size_t broadaddr_size,
    struct sockaddr *dstaddr, size_t dstaddr_size,
    char *errbuf)
{
	netshark_addr_t *curaddr, *prevaddr, *nextaddr;

	/*
	 * Allocate the new entry and fill it in.
	 */
	curaddr = (netshark_addr_t *)malloc(sizeof(netshark_addr_t));
	if (curaddr == NULL) {
		netsharkint_fmt_errmsg_for_errno(errbuf, NETSHARK_ERRBUF_SIZE,
		    errno, "malloc");
		return (-1);
	}

	curaddr->next = NULL;
	if (addr != NULL && addr_size != 0) {
		curaddr->addr = (struct sockaddr *)dup_sockaddr(addr, addr_size);
		if (curaddr->addr == NULL) {
			netsharkint_fmt_errmsg_for_errno(errbuf, NETSHARK_ERRBUF_SIZE,
			    errno, "malloc");
			free(curaddr);
			return (-1);
		}
	} else
		curaddr->addr = NULL;

	if (netmask != NULL && netmask_size != 0) {
		curaddr->netmask = (struct sockaddr *)dup_sockaddr(netmask, netmask_size);
		if (curaddr->netmask == NULL) {
			netsharkint_fmt_errmsg_for_errno(errbuf, NETSHARK_ERRBUF_SIZE,
			    errno, "malloc");
			if (curaddr->addr != NULL)
				free(curaddr->addr);
			free(curaddr);
			return (-1);
		}
	} else
		curaddr->netmask = NULL;

	if (broadaddr != NULL && broadaddr_size != 0) {
		curaddr->broadaddr = (struct sockaddr *)dup_sockaddr(broadaddr, broadaddr_size);
		if (curaddr->broadaddr == NULL) {
			netsharkint_fmt_errmsg_for_errno(errbuf, NETSHARK_ERRBUF_SIZE,
			    errno, "malloc");
			if (curaddr->netmask != NULL)
				free(curaddr->netmask);
			if (curaddr->addr != NULL)
				free(curaddr->addr);
			free(curaddr);
			return (-1);
		}
	} else
		curaddr->broadaddr = NULL;

	if (dstaddr != NULL && dstaddr_size != 0) {
		curaddr->dstaddr = (struct sockaddr *)dup_sockaddr(dstaddr, dstaddr_size);
		if (curaddr->dstaddr == NULL) {
			netsharkint_fmt_errmsg_for_errno(errbuf, NETSHARK_ERRBUF_SIZE,
			    errno, "malloc");
			if (curaddr->broadaddr != NULL)
				free(curaddr->broadaddr);
			if (curaddr->netmask != NULL)
				free(curaddr->netmask);
			if (curaddr->addr != NULL)
				free(curaddr->addr);
			free(curaddr);
			return (-1);
		}
	} else
		curaddr->dstaddr = NULL;

	/*
	 * Find the end of the list of addresses.
	 */
	for (prevaddr = curdev->addresses; prevaddr != NULL; prevaddr = nextaddr) {
		nextaddr = prevaddr->next;
		if (nextaddr == NULL) {
			/*
			 * This is the end of the list.
			 */
			break;
		}
	}

	if (prevaddr == NULL) {
		/*
		 * The list was empty; this is the first member.
		 */
		curdev->addresses = curaddr;
	} else {
		/*
		 * "prevaddr" is the last member of the list; append
		 * this member to it.
		 */
		prevaddr->next = curaddr;
	}

	return (0);
}

/*
 * Look for a given device in the specified list of devices.
 *
 * If we find it, return 0 and set *curdev_ret to point to it.
 *
 * If we don't find it, attempt to add an entry for it, with the specified
 * flags and description, and, if that succeeds, return 0, otherwise
 * return -1 and set errbuf to an error message.
 */
netshark_if_t *
netsharkint_find_or_add_dev(netshark_if_list_t *devlistp, const char *name, bpf_u_int32 flags,
    get_if_flags_func get_flags_func, const char *description, char *errbuf)
{
	netshark_if_t *curdev;

	/*
	 * Is there already an entry in the list for this device?
	 */
	curdev = netsharkint_find_dev(devlistp, name);
	if (curdev != NULL) {
		/*
		 * Yes, return it.
		 */
		return (curdev);
	}

	/*
	 * No, we didn't find it.
	 */

	/*
	 * Try to get additional flags for the device.
	 */
	if ((*get_flags_func)(name, &flags, errbuf) == -1) {
		/*
		 * Failed.
		 */
		return (NULL);
	}

	/*
	 * Now, try to add it to the list of devices.
	 */
	return (netsharkint_add_dev(devlistp, name, flags, description, errbuf));
}

/*
 * Look for a given device in the specified list of devices, and return
 * the entry for it if we find it or NULL if we don't.
 */
netshark_if_t *
netsharkint_find_dev(netshark_if_list_t *devlistp, const char *name)
{
	netshark_if_t *curdev;

	/*
	 * Is there an entry in the list for this device?
	 */
	for (curdev = devlistp->beginning; curdev != NULL;
	    curdev = curdev->next) {
		if (strcmp(name, curdev->name) == 0) {
			/*
			 * We found it, so, yes, there is.  No need to
			 * add it.  Provide the entry we found to our
			 * caller.
			 */
			return (curdev);
		}
	}

	/*
	 * No.
	 */
	return (NULL);
}

/*
 * Attempt to add an entry for a device, with the specified flags
 * and description, and, if that succeeds, return 0 and return a pointer
 * to the new entry, otherwise return NULL and set errbuf to an error
 * message.
 *
 * If we weren't given a description, try to get one.
 */
netshark_if_t *
netsharkint_add_dev(netshark_if_list_t *devlistp, const char *name, bpf_u_int32 flags,
    const char *description, char *errbuf)
{
	netshark_if_t *curdev, *prevdev, *nextdev;
	u_int this_figure_of_merit, nextdev_figure_of_merit;

	curdev = malloc(sizeof(netshark_if_t));
	if (curdev == NULL) {
		netsharkint_fmt_errmsg_for_errno(errbuf, NETSHARK_ERRBUF_SIZE,
		    errno, "malloc");
		return (NULL);
	}

	/*
	 * Fill in the entry.
	 */
	curdev->next = NULL;
	curdev->name = strdup(name);
	if (curdev->name == NULL) {
		netsharkint_fmt_errmsg_for_errno(errbuf, NETSHARK_ERRBUF_SIZE,
		    errno, "malloc");
		free(curdev);
		return (NULL);
	}
	if (description == NULL) {
		/*
		 * We weren't handed a description for the interface.
		 */
		curdev->description = NULL;
	} else {
		/*
		 * We were handed a description; make a copy.
		 */
		curdev->description = strdup(description);
		if (curdev->description == NULL) {
			netsharkint_fmt_errmsg_for_errno(errbuf, NETSHARK_ERRBUF_SIZE,
			    errno, "malloc");
			free(curdev->name);
			free(curdev);
			return (NULL);
		}
	}
	curdev->addresses = NULL;	/* list starts out as empty */
	curdev->flags = flags;

	/*
	 * Add it to the list, in the appropriate location.
	 * First, get the "figure of merit" for this interface.
	 *
	 * To have the list of devices ordered correctly, after adding a
	 * device to the list the device flags value must not change (i.e. it
	 * should be set correctly beforehand).
	 */
	this_figure_of_merit = get_figure_of_merit(curdev);

	/*
	 * Now look for the last interface with an figure of merit
	 * less than or equal to the new interface's figure of merit.
	 *
	 * We start with "prevdev" being NULL, meaning we're before
	 * the first element in the list.
	 */
	prevdev = NULL;
	for (;;) {
		/*
		 * Get the interface after this one.
		 */
		if (prevdev == NULL) {
			/*
			 * The next element is the first element.
			 */
			nextdev = devlistp->beginning;
		} else
			nextdev = prevdev->next;

		/*
		 * Are we at the end of the list?
		 */
		if (nextdev == NULL) {
			/*
			 * Yes - we have to put the new entry after "prevdev".
			 */
			break;
		}

		/*
		 * Is the new interface's figure of merit less
		 * than the next interface's figure of merit,
		 * meaning that the new interface is better
		 * than the next interface?
		 */
		nextdev_figure_of_merit = get_figure_of_merit(nextdev);
		if (this_figure_of_merit < nextdev_figure_of_merit) {
			/*
			 * Yes - we should put the new entry
			 * before "nextdev", i.e. after "prevdev".
			 */
			break;
		}

		prevdev = nextdev;
	}

	/*
	 * Insert before "nextdev".
	 */
	curdev->next = nextdev;

	/*
	 * Insert after "prevdev" - unless "prevdev" is null,
	 * in which case this is the first interface.
	 */
	if (prevdev == NULL) {
		/*
		 * This is the first interface.  Make it
		 * the first element in the list of devices.
		 */
		devlistp->beginning = curdev;
	} else
		prevdev->next = curdev;
	return (curdev);
}

/*
 * Add an entry for the "any" device.
 */
netshark_if_t *
netsharkint_add_any_dev(netshark_if_list_t *devlistp, char *errbuf)
{
	static const char any_descr[] = "Pseudo-device that captures on all interfaces";

	/*
	 * As it refers to all network devices, not to any particular
	 * network device, the notion of "connected" vs. "disconnected"
	 * doesn't apply to the "any" device.
	 */
	return netsharkint_add_dev(devlistp, "any",
	    NETSHARK_IF_UP|NETSHARK_IF_RUNNING|NETSHARK_IF_CONNECTION_STATUS_NOT_APPLICABLE,
	    any_descr, errbuf);
}

/*
 * Free a list of interfaces.
 */
void
netshark_freealldevs(netshark_if_t *alldevs)
{
	netshark_if_t *curdev, *nextdev;
	netshark_addr_t *curaddr, *nextaddr;

	for (curdev = alldevs; curdev != NULL; curdev = nextdev) {
		nextdev = curdev->next;

		/*
		 * Free all addresses.
		 */
		for (curaddr = curdev->addresses; curaddr != NULL; curaddr = nextaddr) {
			nextaddr = curaddr->next;
			if (curaddr->addr)
				free(curaddr->addr);
			if (curaddr->netmask)
				free(curaddr->netmask);
			if (curaddr->broadaddr)
				free(curaddr->broadaddr);
			if (curaddr->dstaddr)
				free(curaddr->dstaddr);
			free(curaddr);
		}

		/*
		 * Free the name string.
		 */
		free(curdev->name);

		/*
		 * Free the description string, if any.
		 */
		if (curdev->description != NULL)
			free(curdev->description);

		/*
		 * Free the interface.
		 */
		free(curdev);
	}
}

/*
 * netshark-npf.c has its own netshark_lookupdev(), for compatibility reasons, as
 * it actually returns the names of all interfaces, with a NUL separator
 * between them; some callers may depend on that.
 *
 * In all other cases, we just use netshark_findalldevs() to get a list of
 * devices, and pick from that list.
 */
#if !defined(HAVE_PACKET32)
/*
 * Return the name of a network interface attached to the system, or NULL
 * if none can be found.  The interface must be configured up; the
 * lowest unit number is preferred; loopback is ignored.
 */
char *
netshark_lookupdev(char *errbuf)
{
	netshark_if_t *alldevs;
#ifdef _WIN32
  /*
   * Windows - use the same size as the old WinPcap 3.1 code.
   * XXX - this is probably bigger than it needs to be.
   */
  #define IF_NAMESIZE 8192
#else
  /*
   * UN*X - use the system's interface name size.
   * XXX - that might not be large enough for capture devices
   * that aren't regular network interfaces.
   */
#endif
	static char device[IF_NAMESIZE + 1];
	char *ret;

	/*
	 * We disable this in "new API" mode, because 1) in WinPcap/Nnetshark,
	 * it may return UTF-16 strings, for backwards-compatibility
	 * reasons, and we're also disabling the hack to make that work,
	 * for not-going-past-the-end-of-a-string reasons, and 2) we
	 * want its behavior to be consistent.
	 *
	 * In addition, it's not thread-safe, so we've marked it as
	 * deprecated.
	 */
	if (netsharkint_new_api) {
		snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
		    "netshark_lookupdev() is deprecated and is not supported in programs calling netshark_init()");
		return (NULL);
	}

	if (netshark_findalldevs(&alldevs, errbuf) == -1)
		return (NULL);

	if (alldevs == NULL || (alldevs->flags & NETSHARK_IF_LOOPBACK)) {
		/*
		 * There are no devices on the list, or the first device
		 * on the list is a loopback device, which means there
		 * are no non-loopback devices on the list.  This means
		 * we can't return any device.
		 *
		 * XXX - why not return a loopback device?  If we can't
		 * capture on it, it won't be on the list, and if it's
		 * on the list, there aren't any non-loopback devices,
		 * so why not just supply it as the default device?
		 */
		(void)netsharkint_strlcpy(errbuf, "no suitable device found",
		    NETSHARK_ERRBUF_SIZE);
		ret = NULL;
	} else {
		/*
		 * Return the name of the first device on the list.
		 */
		(void)netsharkint_strlcpy(device, alldevs->name, sizeof(device));
		ret = device;
	}

	netshark_freealldevs(alldevs);
	return (ret);
}
#endif /* !defined(HAVE_PACKET32) */

#if !defined(_WIN32)
/*
 * We don't just fetch the entire list of devices, search for the
 * particular device, and use its first IPv4 address, as that's too
 * much work to get just one device's netmask.
 *
 * If we had an API to get attributes for a given device, we could
 * use that.
 */
int
netshark_lookupnet(const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp,
    char *errbuf)
{
	register int fd;
	register struct sockaddr_in *sin4;
	struct ifreq ifr;

	/*
	 * The pseudo-device "any" listens on all interfaces and therefore
	 * has the network address and -mask "0.0.0.0" therefore catching
	 * all traffic. Using NULL for the interface is the same as "any".
	 */
	if (!device || strcmp(device, "any") == 0
#ifdef HAVE_DAG_API
	    || strstr(device, "dag") != NULL
#endif
#ifdef NETSHARK_SUPPORT_BT
	    || strstr(device, "bluetooth") != NULL
#endif
#ifdef NETSHARK_SUPPORT_LINUX_USBMON
	    || strstr(device, "usbmon") != NULL
#endif
#ifdef HAVE_SNF_API
	    || strstr(device, "snf") != NULL
#endif
#ifdef NETSHARK_SUPPORT_NETMAP
	    || strncmp(device, "netmap:", 7) == 0
	    || strncmp(device, "vale", 4) == 0
#endif
#ifdef NETSHARK_SUPPORT_DPDK
	    || strncmp(device, "dpdk:", 5) == 0
#endif
	    ) {
		*netp = *maskp = 0;
		return (0);
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		netsharkint_fmt_errmsg_for_errno(errbuf, NETSHARK_ERRBUF_SIZE,
		    errno, "socket");
		return (-1);
	}
	memset(&ifr, 0, sizeof(ifr));
#ifdef __linux__
	/* XXX Work around Linux kernel bug */
	ifr.ifr_addr.sa_family = AF_INET;
#endif
	(void)netsharkint_strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
#if defined(__HAIKU__) && defined(__clang__)
	/*
	 * In Haiku R1/beta4 <unistd.h> ioctl() is a macro that needs to take 4
	 * arguments to initialize its intermediate 2-member structure fully so
	 * that Clang does not generate a -Wmissing-field-initializers warning
	 * (which manifests only when it runs with -Werror).  This workaround
	 * can be removed as soon as there is a Haiku release that fixes the
	 * problem.  See also https://review.haiku-os.org/c/haiku/+/6369
	 */
	if (ioctl(fd, SIOCGIFADDR, (char *)&ifr, sizeof(ifr)) < 0) {
#else
	if (ioctl(fd, SIOCGIFADDR, (char *)&ifr) < 0) {
#endif /* __HAIKU__ && __clang__ */
		if (errno == EADDRNOTAVAIL) {
			(void)snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
			    "%s: no IPv4 address assigned", device);
		} else {
			netsharkint_fmt_errmsg_for_errno(errbuf, NETSHARK_ERRBUF_SIZE,
			    errno, "SIOCGIFADDR: %s", device);
		}
		(void)close(fd);
		return (-1);
	}
	sin4 = (struct sockaddr_in *)&ifr.ifr_addr;
	*netp = sin4->sin_addr.s_addr;
	memset(&ifr, 0, sizeof(ifr));
#ifdef __linux__
	/* XXX Work around Linux kernel bug */
	ifr.ifr_addr.sa_family = AF_INET;
#endif
	(void)netsharkint_strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
#if defined(__HAIKU__) && defined(__clang__)
	/* Same as above. */
	if (ioctl(fd, SIOCGIFNETMASK, (char *)&ifr, sizeof(ifr)) < 0) {
#else
	if (ioctl(fd, SIOCGIFNETMASK, (char *)&ifr) < 0) {
#endif /* __HAIKU__ && __clang__ */
		netsharkint_fmt_errmsg_for_errno(errbuf, NETSHARK_ERRBUF_SIZE,
		    errno, "SIOCGIFNETMASK: %s", device);
		(void)close(fd);
		return (-1);
	}
	(void)close(fd);
	*maskp = sin4->sin_addr.s_addr;
	if (*maskp == 0) {
		if (IN_CLASSA(*netp))
			*maskp = IN_CLASSA_NET;
		else if (IN_CLASSB(*netp))
			*maskp = IN_CLASSB_NET;
		else if (IN_CLASSC(*netp))
			*maskp = IN_CLASSC_NET;
		else {
			(void)snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
			    "inet class for 0x%x unknown", *netp);
			return (-1);
		}
	}
	*netp &= *maskp;
	return (0);
}
#endif /* !defined(_WIN32) */

/*
 * Extract a substring from a string.
 */
static char *
get_substring(const char *p, size_t len, char *ebuf)
{
	char *token;

	token = malloc(len + 1);
	if (token == NULL) {
		netsharkint_fmt_errmsg_for_errno(ebuf, NETSHARK_ERRBUF_SIZE,
		    errno, "malloc");
		return (NULL);
	}
	memcpy(token, p, len);
	token[len] = '\0';
	return (token);
}

/*
 * Parse a capture source that might be a URL.
 *
 * If the source is not a URL, *schemep, *userinfop, *hostp, and *portp
 * are set to NULL, *pathp is set to point to the source, and 0 is
 * returned.
 *
 * If source is a URL, and the URL refers to a local device (a special
 * case of rnetshark:), *schemep, *userinfop, *hostp, and *portp are set
 * to NULL, *pathp is set to point to the device name, and 0 is returned.
 *
 * If source is a URL, and it's not a special case that refers to a local
 * device, and the parse succeeds:
 *
 *    *schemep is set to point to an allocated string containing the scheme;
 *
 *    if user information is present in the URL, *userinfop is set to point
 *    to an allocated string containing the user information, otherwise
 *    it's set to NULL;
 *
 *    if host information is present in the URL, *hostp is set to point
 *    to an allocated string containing the host information, otherwise
 *    it's set to NULL;
 *
 *    if a port number is present in the URL, *portp is set to point
 *    to an allocated string containing the port number, otherwise
 *    it's set to NULL;
 *
 *    *pathp is set to point to an allocated string containing the
 *    path;
 *
 * and 0 is returned.
 *
 * If the parse fails, ebuf is set to an error string, and -1 is returned.
 */
static int
netshark_parse_source(const char *source, char **schemep, char **userinfop,
    char **hostp, char **portp, char **pathp, char *ebuf)
{
	char *colonp;
	size_t scheme_len;
	char *scheme;
	const char *endp;
	size_t authority_len;
	char *authority;
	char *parsep, *atsignp, *bracketp;
	char *userinfo, *host, *port, *path;

	/*
	 * Start out returning nothing.
	 */
	*schemep = NULL;
	*userinfop = NULL;
	*hostp = NULL;
	*portp = NULL;
	*pathp = NULL;

	/*
	 * RFC 3986 says:
	 *
	 *   URI         = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
	 *
	 *   hier-part   = "//" authority path-abempty
	 *               / path-absolute
	 *               / path-rootless
	 *               / path-empty
	 *
	 *   authority   = [ userinfo "@" ] host [ ":" port ]
	 *
	 *   userinfo    = *( unreserved / pct-encoded / sub-delims / ":" )
         *
         * Step 1: look for the ":" at the end of the scheme.
	 * A colon in the source is *NOT* sufficient to indicate that
	 * this is a URL, as interface names on some platforms might
	 * include colons (e.g., I think some Solaris interfaces
	 * might).
	 */
	colonp = strchr(source, ':');
	if (colonp == NULL) {
		/*
		 * The source is the device to open.
		 * Return a NULL pointer for the scheme, user information,
		 * host, and port, and return the device as the path.
		 */
		*pathp = strdup(source);
		if (*pathp == NULL) {
			netsharkint_fmt_errmsg_for_errno(ebuf, NETSHARK_ERRBUF_SIZE,
			    errno, "malloc");
			return (-1);
		}
		return (0);
	}

	/*
	 * All schemes must have "//" after them, i.e. we only support
	 * hier-part   = "//" authority path-abempty, not
	 * hier-part   = path-absolute
	 * hier-part   = path-rootless
	 * hier-part   = path-empty
	 *
	 * We need that in order to distinguish between a local device
	 * name that happens to contain a colon and a URI.
	 */
	if (strncmp(colonp + 1, "//", 2) != 0) {
		/*
		 * The source is the device to open.
		 * Return a NULL pointer for the scheme, user information,
		 * host, and port, and return the device as the path.
		 */
		*pathp = strdup(source);
		if (*pathp == NULL) {
			netsharkint_fmt_errmsg_for_errno(ebuf, NETSHARK_ERRBUF_SIZE,
			    errno, "malloc");
			return (-1);
		}
		return (0);
	}

	/*
	 * XXX - check whether the purported scheme could be a scheme?
	 */

	/*
	 * OK, this looks like a URL.
	 * Get the scheme.
	 */
	scheme_len = colonp - source;
	scheme = malloc(scheme_len + 1);
	if (scheme == NULL) {
		netsharkint_fmt_errmsg_for_errno(ebuf, NETSHARK_ERRBUF_SIZE,
		    errno, "malloc");
		return (-1);
	}
	memcpy(scheme, source, scheme_len);
	scheme[scheme_len] = '\0';

	/*
	 * Treat file: specially - take everything after file:// as
	 * the pathname.
	 */
	if (netsharkint_strcasecmp(scheme, "file") == 0) {
		*pathp = strdup(colonp + 3);
		if (*pathp == NULL) {
			netsharkint_fmt_errmsg_for_errno(ebuf, NETSHARK_ERRBUF_SIZE,
			    errno, "malloc");
			free(scheme);
			return (-1);
		}
		*schemep = scheme;
		return (0);
	}

	/*
	 * The WinPcap documentation says you can specify a local
	 * interface with "rnetshark://{device}"; we special-case
	 * that here.  If the scheme is "rnetshark", and there are
	 * no slashes past the "//", we just return the device.
	 *
	 * XXX - %-escaping?
	 */
	if ((netsharkint_strcasecmp(scheme, "rnetshark") == 0 ||
	    netsharkint_strcasecmp(scheme, "rnetsharks") == 0) &&
	    strchr(colonp + 3, '/') == NULL) {
		/*
		 * Local device.
		 *
		 * Return a NULL pointer for the scheme, user information,
		 * host, and port, and return the device as the path.
		 */
		free(scheme);
		*pathp = strdup(colonp + 3);
		if (*pathp == NULL) {
			netsharkint_fmt_errmsg_for_errno(ebuf, NETSHARK_ERRBUF_SIZE,
			    errno, "malloc");
			return (-1);
		}
		return (0);
	}

	/*
	 * OK, now start parsing the authority.
	 * Get token, terminated with / or terminated at the end of
	 * the string.
	 */
	authority_len = strcspn(colonp + 3, "/");
	authority = get_substring(colonp + 3, authority_len, ebuf);
	if (authority == NULL) {
		/*
		 * Error.
		 */
		free(scheme);
		return (-1);
	}
	endp = colonp + 3 + authority_len;

	/*
	 * Now carve the authority field into its components.
	 */
	parsep = authority;

	/*
	 * Is there a userinfo field?
	 */
	atsignp = strchr(parsep, '@');
	if (atsignp != NULL) {
		/*
		 * Yes.
		 */
		size_t userinfo_len;

		userinfo_len = atsignp - parsep;
		userinfo = get_substring(parsep, userinfo_len, ebuf);
		if (userinfo == NULL) {
			/*
			 * Error.
			 */
			free(authority);
			free(scheme);
			return (-1);
		}
		parsep = atsignp + 1;
	} else {
		/*
		 * No.
		 */
		userinfo = NULL;
	}

	/*
	 * Is there a host field?
	 */
	if (*parsep == '\0') {
		/*
		 * No; there's no host field or port field.
		 */
		host = NULL;
		port = NULL;
	} else {
		/*
		 * Yes.
		 */
		size_t host_len;

		/*
		 * Is it an IP-literal?
		 */
		if (*parsep == '[') {
			/*
			 * Yes.
			 * Treat everything up to the closing square
			 * bracket as the IP-Literal; we don't worry
			 * about whether it's a valid IPv6address or
			 * IPvFuture (or an IPv4address, for that
			 * matter, just in case we get handed a
			 * URL with an IPv4 IP-Literal, of the sort
			 * that netshark_createsrcstr() used to generate,
			 * and that netshark_parsesrcstr(), in the original
			 * WinPcap code, accepted).
			 */
			bracketp = strchr(parsep, ']');
			if (bracketp == NULL) {
				/*
				 * There's no closing square bracket.
				 */
				snprintf(ebuf, NETSHARK_ERRBUF_SIZE,
				    "IP-literal in URL doesn't end with ]");
				free(userinfo);
				free(authority);
				free(scheme);
				return (-1);
			}
			if (*(bracketp + 1) != '\0' &&
			    *(bracketp + 1) != ':') {
				/*
				 * There's extra crud after the
				 * closing square bracket.
				 */
				snprintf(ebuf, NETSHARK_ERRBUF_SIZE,
				    "Extra text after IP-literal in URL");
				free(userinfo);
				free(authority);
				free(scheme);
				return (-1);
			}
			host_len = (bracketp - 1) - parsep;
			host = get_substring(parsep + 1, host_len, ebuf);
			if (host == NULL) {
				/*
				 * Error.
				 */
				free(userinfo);
				free(authority);
				free(scheme);
				return (-1);
			}
			parsep = bracketp + 1;
		} else {
			/*
			 * No.
			 * Treat everything up to a : or the end of
			 * the string as the host.
			 */
			host_len = strcspn(parsep, ":");
			host = get_substring(parsep, host_len, ebuf);
			if (host == NULL) {
				/*
				 * Error.
				 */
				free(userinfo);
				free(authority);
				free(scheme);
				return (-1);
			}
			parsep = parsep + host_len;
		}

		/*
		 * Is there a port field?
		 */
		if (*parsep == ':') {
			/*
			 * Yes.  It's the rest of the authority field.
			 */
			size_t port_len;

			parsep++;
			port_len = strlen(parsep);
			port = get_substring(parsep, port_len, ebuf);
			if (port == NULL) {
				/*
				 * Error.
				 */
				free(host);
				free(userinfo);
				free(authority);
				free(scheme);
				return (-1);
			}
		} else {
			/*
			 * No.
			 */
			port = NULL;
		}
	}
	free(authority);

	/*
	 * Everything else is the path.  Strip off the leading /.
	 */
	if (*endp == '\0')
		path = strdup("");
	else
		path = strdup(endp + 1);
	if (path == NULL) {
		netsharkint_fmt_errmsg_for_errno(ebuf, NETSHARK_ERRBUF_SIZE,
		    errno, "malloc");
		free(port);
		free(host);
		free(userinfo);
		free(scheme);
		return (-1);
	}
	*schemep = scheme;
	*userinfop = userinfo;
	*hostp = host;
	*portp = port;
	*pathp = path;
	return (0);
}

int
netsharkint_createsrcstr_ex(char *source, int type, const char *userinfo, const char *host,
    const char *port, const char *name, unsigned char uses_ssl, char *errbuf)
{
	switch (type) {

	case NETSHARK_SRC_FILE:
		netsharkint_strlcpy(source, NETSHARK_SRC_FILE_STRING, NETSHARK_BUF_SIZE);
		if (name != NULL && *name != '\0') {
			netsharkint_strlcat(source, name, NETSHARK_BUF_SIZE);
			return (0);
		} else {
			snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
			    "The file name cannot be NULL.");
			return (-1);
		}

	case NETSHARK_SRC_IFREMOTE:
		netsharkint_strlcpy(source,
		    (uses_ssl ? "rnetsharks://" : NETSHARK_SRC_IF_STRING),
		    NETSHARK_BUF_SIZE);
		if (host != NULL && *host != '\0') {
			if (userinfo != NULL && *userinfo != '\0') {
				netsharkint_strlcat(source, userinfo, NETSHARK_BUF_SIZE);
				netsharkint_strlcat(source, "@", NETSHARK_BUF_SIZE);
			}

			if (strchr(host, ':') != NULL) {
				/*
				 * The host name contains a colon, so it's
				 * probably an IPv6 address, and needs to
				 * be included in square brackets.
				 */
				netsharkint_strlcat(source, "[", NETSHARK_BUF_SIZE);
				netsharkint_strlcat(source, host, NETSHARK_BUF_SIZE);
				netsharkint_strlcat(source, "]", NETSHARK_BUF_SIZE);
			} else
				netsharkint_strlcat(source, host, NETSHARK_BUF_SIZE);

			if (port != NULL && *port != '\0') {
				netsharkint_strlcat(source, ":", NETSHARK_BUF_SIZE);
				netsharkint_strlcat(source, port, NETSHARK_BUF_SIZE);
			}

			netsharkint_strlcat(source, "/", NETSHARK_BUF_SIZE);
		} else {
			snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
			    "The host name cannot be NULL.");
			return (-1);
		}

		if (name != NULL && *name != '\0')
			netsharkint_strlcat(source, name, NETSHARK_BUF_SIZE);

		return (0);

	case NETSHARK_SRC_IFLOCAL:
		netsharkint_strlcpy(source, NETSHARK_SRC_IF_STRING, NETSHARK_BUF_SIZE);

		if (name != NULL && *name != '\0')
			netsharkint_strlcat(source, name, NETSHARK_BUF_SIZE);

		return (0);

	default:
		snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
		    "The interface type is not valid.");
		return (-1);
	}
}


int
netshark_createsrcstr(char *source, int type, const char *host, const char *port,
    const char *name, char *errbuf)
{
	return (netsharkint_createsrcstr_ex(source, type, NULL, host, port, name, 0, errbuf));
}

int
netsharkint_parsesrcstr_ex(const char *source, int *type, char *userinfo, char *host,
    char *port, char *name, unsigned char *uses_ssl, char *errbuf)
{
	char *scheme, *tmpuserinfo, *tmphost, *tmpport, *tmppath;

	/* Initialization stuff */
	if (userinfo)
		*userinfo = '\0';
	if (host)
		*host = '\0';
	if (port)
		*port = '\0';
	if (name)
		*name = '\0';
	if (uses_ssl)
		*uses_ssl = 0;

	/* Parse the source string */
	if (netshark_parse_source(source, &scheme, &tmpuserinfo, &tmphost,
	    &tmpport, &tmppath, errbuf) == -1) {
		/*
		 * Fail.
		 */
		return (-1);
	}

	if (scheme == NULL) {
		/*
		 * Local device.
		 */
		if (name && tmppath)
			netsharkint_strlcpy(name, tmppath, NETSHARK_BUF_SIZE);
		if (type)
			*type = NETSHARK_SRC_IFLOCAL;
		free(tmppath);
		free(tmpport);
		free(tmphost);
		free(tmpuserinfo);
		return (0);
	}

	int is_rnetshark = 0;
	if (strcmp(scheme, "rnetsharks") == 0) {
		is_rnetshark = 1;
		if (uses_ssl) *uses_ssl = 1;
	} else if (strcmp(scheme, "rnetshark") == 0) {
		is_rnetshark = 1;
	}

	if (is_rnetshark) {
		/*
		 * rnetshark[s]://
		 *
		 * netshark_parse_source() has already handled the case of
		 * rnetshark[s]://device
		 */
		if (userinfo && tmpuserinfo)
			netsharkint_strlcpy(userinfo, tmpuserinfo, NETSHARK_BUF_SIZE);
		if (host && tmphost)
			netsharkint_strlcpy(host, tmphost, NETSHARK_BUF_SIZE);
		if (port && tmpport)
			netsharkint_strlcpy(port, tmpport, NETSHARK_BUF_SIZE);
		if (name && tmppath)
			netsharkint_strlcpy(name, tmppath, NETSHARK_BUF_SIZE);
		if (type)
			*type = NETSHARK_SRC_IFREMOTE;
		free(tmppath);
		free(tmpport);
		free(tmphost);
		free(tmpuserinfo);
		free(scheme);
		return (0);
	}

	if (strcmp(scheme, "file") == 0) {
		/*
		 * file://
		 */
		if (name && tmppath)
			netsharkint_strlcpy(name, tmppath, NETSHARK_BUF_SIZE);
		if (type)
			*type = NETSHARK_SRC_FILE;
		free(tmppath);
		free(tmpport);
		free(tmphost);
		free(tmpuserinfo);
		free(scheme);
		return (0);
	}

	/*
	 * Neither rnetshark: nor file:; just treat the entire string
	 * as a local device.
	 */
	if (name)
		netsharkint_strlcpy(name, source, NETSHARK_BUF_SIZE);
	if (type)
		*type = NETSHARK_SRC_IFLOCAL;
	free(tmppath);
	free(tmpport);
	free(tmphost);
	free(tmpuserinfo);
	free(scheme);
	return (0);
}

int
netshark_parsesrcstr(const char *source, int *type, char *host, char *port,
    char *name, char *errbuf)
{
	return (netsharkint_parsesrcstr_ex(source, type, NULL, host, port, name, NULL, errbuf));
}

netshark_t *
netshark_create(const char *device, char *errbuf)
{
	size_t i;
	int is_theirs;
	netshark_t *p;
	char *device_str;

	/*
	 * A null device name is equivalent to the "any" device -
	 * which might not be supported on this platform, but
	 * this means that you'll get a "not supported" error
	 * rather than, say, a crash when we try to dereference
	 * the null pointer.
	 */
	if (device == NULL)
		device_str = strdup("any");
	else {
#ifdef _WIN32
		/*
		 * On Windows, for backwards compatibility reasons,
		 * netshark_lookupdev() returns a pointer to a sequence of
		 * pairs of UTF-16LE device names and local code page
		 * description strings.
		 *
		 * This means that if a program uses netshark_lookupdev()
		 * to get a default device, and hands that to an API
		 * that opens devices, we'll get handed a UTF-16LE
		 * string, not a string in the local code page.
		 *
		 * To work around that, we check whether the string
		 * looks as if it might be a UTF-16LE string and, if
		 * so, convert it back to the local code page's
		 * extended ASCII.
		 *
		 * We disable that check in "new API" mode, because:
		 *
		 *   1) You *cannot* reliably detect whether a
		 *   string is UTF-16LE or not; "a" could either
		 *   be a one-character ASCII string or the first
		 *   character of a UTF-16LE string.
		 *
		 *   2) Doing that test can run past the end of
		 *   the string, if it's a 1-character ASCII
		 *   string
		 *
		 * This particular version of this heuristic dates
		 * back to WinPcap 4.1.1; PacketOpenAdapter() does
		 * uses the same heuristic, with the exact same
		 * vulnerability.
		 *
		 * That's why we disable this in "new API" mode.
		 * We keep it around in legacy mode for backwards
		 * compatibility.
		 */
		if (!netsharkint_new_api && device[0] != '\0' && device[1] == '\0') {
			size_t length;

			length = wcslen((wchar_t *)device);
			device_str = (char *)malloc(length + 1);
			if (device_str == NULL) {
				netsharkint_fmt_errmsg_for_errno(errbuf,
				    NETSHARK_ERRBUF_SIZE, errno,
				    "malloc");
				return (NULL);
			}

			snprintf(device_str, length + 1, "%ws",
			    (const wchar_t *)device);
		} else
#endif
			device_str = strdup(device);
	}
	if (device_str == NULL) {
		netsharkint_fmt_errmsg_for_errno(errbuf, NETSHARK_ERRBUF_SIZE,
		    errno, "malloc");
		return (NULL);
	}

	/*
	 * Try each of the non-local-network-interface capture
	 * source types until we find one that works for this
	 * device or run out of types.
	 */
	for (i = 0; capture_source_types[i].create_op != NULL; i++) {
		is_theirs = 0;
		p = capture_source_types[i].create_op(device_str, errbuf,
		    &is_theirs);
		if (is_theirs) {
			/*
			 * The device name refers to a device of the
			 * type in question; either it succeeded,
			 * in which case p refers to a netshark_t to
			 * later activate for the device, or it
			 * failed, in which case p is null and we
			 * should return that to report the failure
			 * to create.
			 */
			if (p == NULL) {
				/*
				 * We assume the caller filled in errbuf.
				 */
				free(device_str);
				return (NULL);
			}
			p->opt.device = device_str;
			return (p);
		}
	}

	/*
	 * OK, try it as a regular network interface.
	 */
	p = netsharkint_create_interface(device_str, errbuf);
	if (p == NULL) {
		/*
		 * We assume the caller filled in errbuf.
		 */
		free(device_str);
		return (NULL);
	}
	p->opt.device = device_str;
	return (p);
}

/*
 * Set nonblocking mode on an unactivated netshark_t; this sets a flag
 * checked by netshark_activate(), which sets the mode after calling
 * the activate routine.
 */
static int
netshark_setnonblock_unactivated(netshark_t *p, int nonblock)
{
	p->opt.nonblock = nonblock;
	return (0);
}

static void
initialize_ops(netshark_t *p)
{
	/*
	 * Set operation pointers for operations that only work on
	 * an activated netshark_t to point to a routine that returns
	 * a "this isn't activated" error.
	 */
	p->read_op = netshark_read_not_initialized;
	p->inject_op = netshark_inject_not_initialized;
	p->setfilter_op = netshark_setfilter_not_initialized;
	p->setdirection_op = netshark_setdirection_not_initialized;
	p->set_datalink_op = netshark_set_datalink_not_initialized;
	p->getnonblock_op = netshark_getnonblock_not_initialized;
	p->stats_op = netshark_stats_not_initialized;
#ifdef _WIN32
	p->stats_ex_op = netshark_stats_ex_not_initialized;
	p->setbuff_op = netshark_setbuff_not_initialized;
	p->setmode_op = netshark_setmode_not_initialized;
	p->setmintocopy_op = netshark_setmintocopy_not_initialized;
	p->getevent_op = netshark_getevent_not_initialized;
	p->oid_get_request_op = netshark_oid_get_request_not_initialized;
	p->oid_set_request_op = netshark_oid_set_request_not_initialized;
	p->sendqueue_transmit_op = netshark_sendqueue_transmit_not_initialized;
	p->setuserbuffer_op = netshark_setuserbuffer_not_initialized;
	p->live_dump_op = netshark_live_dump_not_initialized;
	p->live_dump_ended_op = netshark_live_dump_ended_not_initialized;
#endif

	/*
	 * Default cleanup operation - implementations can override
	 * this, but should call netsharkint_cleanup_live_common() after
	 * doing their own additional cleanup.
	 */
	p->cleanup_op = netsharkint_cleanup_live_common;

	/*
	 * In most cases, the standard one-shot callback can
	 * be used for netshark_next()/netshark_next_ex().
	 */
	p->oneshot_callback = netsharkint_oneshot;

	/*
	 * Default breakloop operation - implementations can override
	 * this, but should call netsharkint_breakloop_common() before doing
	 * their own logic.
	 */
	p->breakloop_op = netsharkint_breakloop_common;
}

static netshark_t *
netshark_alloc_netshark_t(char *ebuf, size_t total_size, size_t private_offset)
{
	char *chunk;
	netshark_t *p;

	/*
	 * total_size is the size of a structure containing a netshark_t
	 * followed by a private structure.
	 */
	chunk = calloc(total_size, 1);
	if (chunk == NULL) {
		netsharkint_fmt_errmsg_for_errno(ebuf, NETSHARK_ERRBUF_SIZE,
		    errno, "malloc");
		return (NULL);
	}

	/*
	 * Get a pointer to the netshark_t at the beginning.
	 */
	p = (netshark_t *)chunk;

#ifdef _WIN32
	p->handle = INVALID_HANDLE_VALUE;	/* not opened yet */
#else /* _WIN32 */
	p->fd = -1;	/* not opened yet */
	p->selectable_fd = -1;
	p->required_select_timeout = NULL;
#endif /* _WIN32 */

	/*
	 * private_offset is the offset, in bytes, of the private
	 * data from the beginning of the structure.
	 *
	 * Set the pointer to the private data; that's private_offset
	 * bytes past the netshark_t.
	 */
	p->priv = (void *)(chunk + private_offset);

	return (p);
}

netshark_t *
netsharkint_create_common(char *ebuf, size_t total_size, size_t private_offset)
{
	netshark_t *p;

	p = netshark_alloc_netshark_t(ebuf, total_size, private_offset);
	if (p == NULL)
		return (NULL);

	/*
	 * Default to "can't set rfmon mode"; if it's supported by
	 * a platform, the create routine that called us can set
	 * the op to its routine to check whether a particular
	 * device supports it.
	 */
	p->can_set_rfmon_op = netshark_cant_set_rfmon;

	/*
	 * If netshark_setnonblock() is called on a not-yet-activated
	 * netshark_t, default to setting a flag and turning
	 * on non-blocking mode when activated.
	 */
	p->setnonblock_op = netshark_setnonblock_unactivated;

	initialize_ops(p);

	/* put in some defaults*/
	p->snapshot = 0;		/* max packet size unspecified */
	p->opt.timeout = 0;		/* no timeout specified */
	p->opt.buffer_size = 0;		/* use the platform's default */
	p->opt.promisc = 0;
	p->opt.rfmon = 0;
	p->opt.immediate = 0;
	p->opt.tstamp_type = -1;	/* default to not setting time stamp type */
	p->opt.tstamp_precision = NETSHARK_TSTAMP_PRECISION_MICRO;
	/*
	 * Platform-dependent options.
	 */
#ifdef __linux__
	p->opt.protocol = 0;
#endif
#ifdef _WIN32
	p->opt.nocapture_local = 0;
#endif

	/*
	 * Start out with no BPF code generation flags set.
	 */
	p->bpf_codegen_flags = 0;

	return (p);
}

int
netsharkint_check_activated(netshark_t *p)
{
	if (p->activated) {
		snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE, "can't perform "
			" operation on activated capture");
		return (-1);
	}
	return (0);
}

int
netshark_set_snaplen(netshark_t *p, int snaplen)
{
	if (netsharkint_check_activated(p))
		return (NETSHARK_ERROR_ACTIVATED);
	p->snapshot = snaplen;
	return (0);
}

int
netshark_set_promisc(netshark_t *p, int promisc)
{
	if (netsharkint_check_activated(p))
		return (NETSHARK_ERROR_ACTIVATED);
	p->opt.promisc = promisc;
	return (0);
}

int
netshark_set_rfmon(netshark_t *p, int rfmon)
{
	if (netsharkint_check_activated(p))
		return (NETSHARK_ERROR_ACTIVATED);
	p->opt.rfmon = rfmon;
	return (0);
}

int
netshark_set_timeout(netshark_t *p, int timeout_ms)
{
	if (netsharkint_check_activated(p))
		return (NETSHARK_ERROR_ACTIVATED);
	p->opt.timeout = timeout_ms;
	return (0);
}

int
netshark_set_tstamp_type(netshark_t *p, int tstamp_type)
{
	int i;

	if (netsharkint_check_activated(p))
		return (NETSHARK_ERROR_ACTIVATED);

	/*
	 * The argument should have been u_int, but that's too late
	 * to change now - it's an API.
	 */
	if (tstamp_type < 0)
		return (NETSHARK_WARNING_TSTAMP_TYPE_NOTSUP);

	/*
	 * If p->tstamp_type_count is 0, we only support NETSHARK_TSTAMP_HOST;
	 * the default time stamp type is NETSHARK_TSTAMP_HOST.
	 */
	if (p->tstamp_type_count == 0) {
		if (tstamp_type == NETSHARK_TSTAMP_HOST) {
			p->opt.tstamp_type = tstamp_type;
			return (0);
		}
	} else {
		/*
		 * Check whether we claim to support this type of time stamp.
		 */
		for (i = 0; i < p->tstamp_type_count; i++) {
			if (p->tstamp_type_list[i] == (u_int)tstamp_type) {
				/*
				 * Yes.
				 */
				p->opt.tstamp_type = tstamp_type;
				return (0);
			}
		}
	}

	/*
	 * We don't support this type of time stamp.
	 */
	return (NETSHARK_WARNING_TSTAMP_TYPE_NOTSUP);
}

int
netshark_set_immediate_mode(netshark_t *p, int immediate)
{
	if (netsharkint_check_activated(p))
		return (NETSHARK_ERROR_ACTIVATED);
	p->opt.immediate = immediate;
	return (0);
}

int
netshark_set_buffer_size(netshark_t *p, int buffer_size)
{
	if (netsharkint_check_activated(p))
		return (NETSHARK_ERROR_ACTIVATED);
	if (buffer_size <= 0) {
		/*
		 * Silently ignore invalid values.
		 */
		return (0);
	}
	p->opt.buffer_size = buffer_size;
	return (0);
}

int
netshark_set_tstamp_precision(netshark_t *p, int tstamp_precision)
{
	int i;

	if (netsharkint_check_activated(p))
		return (NETSHARK_ERROR_ACTIVATED);

	/*
	 * The argument should have been u_int, but that's too late
	 * to change now - it's an API.
	 */
	if (tstamp_precision < 0)
		return (NETSHARK_ERROR_TSTAMP_PRECISION_NOTSUP);

	/*
	 * If p->tstamp_precision_count is 0, we only support setting
	 * the time stamp precision to microsecond precision; every
	 * netshark module *MUST* support microsecond precision, even if
	 * it does so by converting the native precision to
	 * microseconds.
	 */
	if (p->tstamp_precision_count == 0) {
		if (tstamp_precision == NETSHARK_TSTAMP_PRECISION_MICRO) {
			p->opt.tstamp_precision = tstamp_precision;
			return (0);
		}
	} else {
		/*
		 * Check whether we claim to support this precision of
		 * time stamp.
		 */
		for (i = 0; i < p->tstamp_precision_count; i++) {
			if (p->tstamp_precision_list[i] == (u_int)tstamp_precision) {
				/*
				 * Yes.
				 */
				p->opt.tstamp_precision = tstamp_precision;
				return (0);
			}
		}
	}

	/*
	 * We don't support this time stamp precision.
	 */
	return (NETSHARK_ERROR_TSTAMP_PRECISION_NOTSUP);
}

int
netshark_get_tstamp_precision(netshark_t *p)
{
        return (p->opt.tstamp_precision);
}

int
netshark_activate(netshark_t *p)
{
	int status;

	/*
	 * Catch attempts to re-activate an already-activated
	 * netshark_t; this should, for example, catch code that
	 * calls netshark_open_live() followed by netshark_activate(),
	 * as some code that showed up in a Stack Exchange
	 * question did.
	 */
	if (netsharkint_check_activated(p))
		return (NETSHARK_ERROR_ACTIVATED);
	status = p->activate_op(p);
	if (status >= 0) {
		/*
		 * If somebody requested non-blocking mode before
		 * calling netshark_activate(), turn it on now.
		 */
		if (p->opt.nonblock) {
			status = p->setnonblock_op(p, 1);
			if (status < 0) {
				/*
				 * Failed.  Undo everything done by
				 * the activate operation.
				 */
				p->cleanup_op(p);
				initialize_ops(p);
				return (status);
			}
		}
		p->activated = 1;
	} else {
		if (p->errbuf[0] == '\0') {
			/*
			 * No error message supplied by the activate routine;
			 * for the benefit of programs that don't specially
			 * handle errors other than NETSHARK_ERROR, return the
			 * error message corresponding to the status.
			 */
			snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE, "%s",
			    netshark_statustostr(status));
		}

		/*
		 * Undo any operation pointer setting, etc. done by
		 * the activate operation.
		 */
		initialize_ops(p);
	}
	return (status);
}

netshark_t *
netshark_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf)
{
	netshark_t *p;
	int status;
#ifdef ENABLE_REMOTE
	char host[NETSHARK_BUF_SIZE + 1];
	char port[NETSHARK_BUF_SIZE + 1];
	char name[NETSHARK_BUF_SIZE + 1];
	int srctype;

	/*
	 * A null device name is equivalent to the "any" device -
	 * which might not be supported on this platform, but
	 * this means that you'll get a "not supported" error
	 * rather than, say, a crash when we try to dereference
	 * the null pointer.
	 */
	if (device == NULL)
		device = "any";

	/*
	 * Retrofit - we have to make older applications compatible with
	 * remote capture.
	 * So we're calling netshark_open_remote() from here; this is a very
	 * dirty hack.
	 * Obviously, we cannot exploit all the new features; for instance,
	 * we cannot send authentication, we cannot use a UDP data connection,
	 * and so on.
	 */
	if (netshark_parsesrcstr(device, &srctype, host, port, name, errbuf))
		return (NULL);

	if (srctype == NETSHARK_SRC_IFREMOTE) {
		/*
		 * Although we already have host, port and iface, we prefer
		 * to pass only 'device' to netshark_open_rnetshark(), so that it has
		 * to call netshark_parsesrcstr() again.
		 * This is less optimized, but much clearer.
		 */
		return (netshark_open_rnetshark(device, snaplen,
		    promisc ? NETSHARK_OPENFLAG_PROMISCUOUS : 0, to_ms,
		    NULL, errbuf));
	}
	if (srctype == NETSHARK_SRC_FILE) {
		snprintf(errbuf, NETSHARK_ERRBUF_SIZE, "unknown URL scheme \"file\"");
		return (NULL);
	}
	if (srctype == NETSHARK_SRC_IFLOCAL) {
		/*
		 * If it starts with rnetshark://, that refers to a local device
		 * (no host part in the URL). Remove the rnetshark://, and
		 * fall through to the regular open path.
		 */
		if (strncmp(device, NETSHARK_SRC_IF_STRING, strlen(NETSHARK_SRC_IF_STRING)) == 0) {
			size_t len = strlen(device) - strlen(NETSHARK_SRC_IF_STRING) + 1;

			if (len > 0)
				device += strlen(NETSHARK_SRC_IF_STRING);
		}
	}
#endif	/* ENABLE_REMOTE */

	p = netshark_create(device, errbuf);
	if (p == NULL)
		return (NULL);
	status = netshark_set_snaplen(p, snaplen);
	if (status < 0)
		goto fail;
	status = netshark_set_promisc(p, promisc);
	if (status < 0)
		goto fail;
	status = netshark_set_timeout(p, to_ms);
	if (status < 0)
		goto fail;
	/*
	 * Mark this as opened with netshark_open_live(), so that, for
	 * example, we show the full list of DLT_ values, rather
	 * than just the ones that are compatible with capturing
	 * when not in monitor mode.  That allows existing applications
	 * to work the way they used to work, but allows new applications
	 * that know about the new open API to, for example, find out the
	 * DLT_ values that they can select without changing whether
	 * the adapter is in monitor mode or not.
	 */
	p->oldstyle = 1;
	status = netshark_activate(p);
	if (status < 0)
		goto fail;
	return (p);
fail:
	if (status == NETSHARK_ERROR) {
		/*
		 * Another buffer is a bit cumbersome, but it avoids
		 * -Wformat-truncation.
		 */
		char trimbuf[NETSHARK_ERRBUF_SIZE - 5]; /* 2 bytes shorter */

		netsharkint_strlcpy(trimbuf, p->errbuf, sizeof(trimbuf));
		snprintf(errbuf, NETSHARK_ERRBUF_SIZE, "%s: %.*s", device,
		    NETSHARK_ERRBUF_SIZE - 3, trimbuf);
	} else if (status == NETSHARK_ERROR_NO_SUCH_DEVICE ||
	    status == NETSHARK_ERROR_PERM_DENIED ||
	    status == NETSHARK_ERROR_PROMISC_PERM_DENIED) {
		/*
		 * Only show the additional message if it's not
		 * empty.
		 */
		if (p->errbuf[0] != '\0') {
			/*
			 * Idem.
			 */
			char trimbuf[NETSHARK_ERRBUF_SIZE - 8]; /* 2 bytes shorter */

			netsharkint_strlcpy(trimbuf, p->errbuf, sizeof(trimbuf));
			snprintf(errbuf, NETSHARK_ERRBUF_SIZE, "%s: %s (%.*s)",
			    device, netshark_statustostr(status),
			    NETSHARK_ERRBUF_SIZE - 6, trimbuf);
		} else {
			snprintf(errbuf, NETSHARK_ERRBUF_SIZE, "%s: %s",
			    device, netshark_statustostr(status));
		}
	} else {
		snprintf(errbuf, NETSHARK_ERRBUF_SIZE, "%s: %s", device,
		    netshark_statustostr(status));
	}
	netshark_close(p);
	return (NULL);
}

netshark_t *
netsharkint_open_offline_common(char *ebuf, size_t total_size, size_t private_offset)
{
	netshark_t *p;

	p = netshark_alloc_netshark_t(ebuf, total_size, private_offset);
	if (p == NULL)
		return (NULL);

	p->opt.tstamp_precision = NETSHARK_TSTAMP_PRECISION_MICRO;

	return (p);
}

int
netshark_dispatch(netshark_t *p, int cnt, netshark_handler callback, u_char *user)
{
	return (p->read_op(p, cnt, callback, user));
}

int
netshark_loop(netshark_t *p, int cnt, netshark_handler callback, u_char *user)
{
	register int n;

	for (;;) {
		if (p->rfile != NULL) {
			/*
			 * 0 means EOF, so don't loop if we get 0.
			 */
			n = netsharkint_offline_read(p, cnt, callback, user);
		} else {
			/*
			 * XXX keep reading until we get something
			 * (or an error occurs)
			 */
			do {
				n = p->read_op(p, cnt, callback, user);
			} while (n == 0);
		}
		if (n <= 0)
			return (n);
		if (!PACKET_COUNT_IS_UNLIMITED(cnt)) {
			cnt -= n;
			if (cnt <= 0)
				return (0);
		}
	}
}

/*
 * Force the loop in "netshark_read()" or "netshark_read_offline()" to terminate.
 */
void
netshark_breakloop(netshark_t *p)
{
	p->breakloop_op(p);
}

int
netshark_datalink(netshark_t *p)
{
	if (!p->activated)
		return (NETSHARK_ERROR_NOT_ACTIVATED);
	return (p->linktype);
}

int
netshark_datalink_ext(netshark_t *p)
{
	if (!p->activated)
		return (NETSHARK_ERROR_NOT_ACTIVATED);
	return (p->linktype_ext);
}

int
netshark_list_datalinks(netshark_t *p, int **dlt_buffer)
{
	if (!p->activated)
		return (NETSHARK_ERROR_NOT_ACTIVATED);
	if (p->dlt_count == 0) {
		/*
		 * We couldn't fetch the list of DLTs, which means
		 * this platform doesn't support changing the
		 * DLT for an interface.  Return a list of DLTs
		 * containing only the DLT this device supports.
		 */
		*dlt_buffer = (int*)malloc(sizeof(**dlt_buffer));
		if (*dlt_buffer == NULL) {
			netsharkint_fmt_errmsg_for_errno(p->errbuf, sizeof(p->errbuf),
			    errno, "malloc");
			return (NETSHARK_ERROR);
		}
		**dlt_buffer = p->linktype;
		return (1);
	} else {
		*dlt_buffer = (int*)calloc(p->dlt_count, sizeof(**dlt_buffer));
		if (*dlt_buffer == NULL) {
			netsharkint_fmt_errmsg_for_errno(p->errbuf, sizeof(p->errbuf),
			    errno, "malloc");
			return (NETSHARK_ERROR);
		}
		(void)memcpy(*dlt_buffer, p->dlt_list,
		    sizeof(**dlt_buffer) * p->dlt_count);
		return (p->dlt_count);
	}
}

/*
 * In Windows, you might have a library built with one version of the
 * C runtime library and an application built with another version of
 * the C runtime library, which means that the library might use one
 * version of malloc() and free() and the application might use another
 * version of malloc() and free().  If so, that means something
 * allocated by the library cannot be freed by the application, so we
 * need to have a netshark_free_datalinks() routine to free up the list
 * allocated by netshark_list_datalinks(), even though it's just a wrapper
 * around free().
 */
void
netshark_free_datalinks(int *dlt_list)
{
	free(dlt_list);
}

int
netshark_set_datalink(netshark_t *p, int dlt)
{
	int i;
	const char *dlt_name;

	if (dlt < 0)
		goto unsupported;

	if (p->dlt_count == 0 || p->set_datalink_op == NULL) {
		/*
		 * We couldn't fetch the list of DLTs, or we don't
		 * have a "set datalink" operation, which means
		 * this platform doesn't support changing the
		 * DLT for an interface.  Check whether the new
		 * DLT is the one this interface supports.
		 */
		if (p->linktype != dlt)
			goto unsupported;

		/*
		 * It is, so there's nothing we need to do here.
		 */
		return (0);
	}
	for (i = 0; i < p->dlt_count; i++)
		if (p->dlt_list[i] == (u_int)dlt)
			break;
	if (i >= p->dlt_count)
		goto unsupported;
	if (p->dlt_count == 2 && p->dlt_list[0] == DLT_EN10MB &&
	    dlt == DLT_DOCSIS) {
		/*
		 * This is presumably an Ethernet device, as the first
		 * link-layer type it offers is DLT_EN10MB, and the only
		 * other type it offers is DLT_DOCSIS.  That means that
		 * we can't tell the driver to supply DOCSIS link-layer
		 * headers - we're just pretending that's what we're
		 * getting, as, presumably, we're capturing on a dedicated
		 * link to a Cisco Cable Modem Termination System, and
		 * it's putting raw DOCSIS frames on the wire inside low-level
		 * Ethernet framing.
		 */
		p->linktype = dlt;
		return (0);
	}
	if (p->set_datalink_op(p, dlt) == -1)
		return (-1);
	p->linktype = dlt;
	return (0);

unsupported:
	dlt_name = netshark_datalink_val_to_name(dlt);
	if (dlt_name != NULL) {
		(void) snprintf(p->errbuf, sizeof(p->errbuf),
		    "%s is not one of the DLTs supported by this device",
		    dlt_name);
	} else {
		(void) snprintf(p->errbuf, sizeof(p->errbuf),
		    "DLT %d is not one of the DLTs supported by this device",
		    dlt);
	}
	return (-1);
}

/*
 * This array is designed for mapping upper and lower case letter
 * together for a case independent comparison.  The mappings are
 * based upon ascii character sequences.
 */
static const u_char charmap[] = {
	(u_char)'\000', (u_char)'\001', (u_char)'\002', (u_char)'\003',
	(u_char)'\004', (u_char)'\005', (u_char)'\006', (u_char)'\007',
	(u_char)'\010', (u_char)'\011', (u_char)'\012', (u_char)'\013',
	(u_char)'\014', (u_char)'\015', (u_char)'\016', (u_char)'\017',
	(u_char)'\020', (u_char)'\021', (u_char)'\022', (u_char)'\023',
	(u_char)'\024', (u_char)'\025', (u_char)'\026', (u_char)'\027',
	(u_char)'\030', (u_char)'\031', (u_char)'\032', (u_char)'\033',
	(u_char)'\034', (u_char)'\035', (u_char)'\036', (u_char)'\037',
	(u_char)'\040', (u_char)'\041', (u_char)'\042', (u_char)'\043',
	(u_char)'\044', (u_char)'\045', (u_char)'\046', (u_char)'\047',
	(u_char)'\050', (u_char)'\051', (u_char)'\052', (u_char)'\053',
	(u_char)'\054', (u_char)'\055', (u_char)'\056', (u_char)'\057',
	(u_char)'\060', (u_char)'\061', (u_char)'\062', (u_char)'\063',
	(u_char)'\064', (u_char)'\065', (u_char)'\066', (u_char)'\067',
	(u_char)'\070', (u_char)'\071', (u_char)'\072', (u_char)'\073',
	(u_char)'\074', (u_char)'\075', (u_char)'\076', (u_char)'\077',
	(u_char)'\100', (u_char)'\141', (u_char)'\142', (u_char)'\143',
	(u_char)'\144', (u_char)'\145', (u_char)'\146', (u_char)'\147',
	(u_char)'\150', (u_char)'\151', (u_char)'\152', (u_char)'\153',
	(u_char)'\154', (u_char)'\155', (u_char)'\156', (u_char)'\157',
	(u_char)'\160', (u_char)'\161', (u_char)'\162', (u_char)'\163',
	(u_char)'\164', (u_char)'\165', (u_char)'\166', (u_char)'\167',
	(u_char)'\170', (u_char)'\171', (u_char)'\172', (u_char)'\133',
	(u_char)'\134', (u_char)'\135', (u_char)'\136', (u_char)'\137',
	(u_char)'\140', (u_char)'\141', (u_char)'\142', (u_char)'\143',
	(u_char)'\144', (u_char)'\145', (u_char)'\146', (u_char)'\147',
	(u_char)'\150', (u_char)'\151', (u_char)'\152', (u_char)'\153',
	(u_char)'\154', (u_char)'\155', (u_char)'\156', (u_char)'\157',
	(u_char)'\160', (u_char)'\161', (u_char)'\162', (u_char)'\163',
	(u_char)'\164', (u_char)'\165', (u_char)'\166', (u_char)'\167',
	(u_char)'\170', (u_char)'\171', (u_char)'\172', (u_char)'\173',
	(u_char)'\174', (u_char)'\175', (u_char)'\176', (u_char)'\177',
	(u_char)'\200', (u_char)'\201', (u_char)'\202', (u_char)'\203',
	(u_char)'\204', (u_char)'\205', (u_char)'\206', (u_char)'\207',
	(u_char)'\210', (u_char)'\211', (u_char)'\212', (u_char)'\213',
	(u_char)'\214', (u_char)'\215', (u_char)'\216', (u_char)'\217',
	(u_char)'\220', (u_char)'\221', (u_char)'\222', (u_char)'\223',
	(u_char)'\224', (u_char)'\225', (u_char)'\226', (u_char)'\227',
	(u_char)'\230', (u_char)'\231', (u_char)'\232', (u_char)'\233',
	(u_char)'\234', (u_char)'\235', (u_char)'\236', (u_char)'\237',
	(u_char)'\240', (u_char)'\241', (u_char)'\242', (u_char)'\243',
	(u_char)'\244', (u_char)'\245', (u_char)'\246', (u_char)'\247',
	(u_char)'\250', (u_char)'\251', (u_char)'\252', (u_char)'\253',
	(u_char)'\254', (u_char)'\255', (u_char)'\256', (u_char)'\257',
	(u_char)'\260', (u_char)'\261', (u_char)'\262', (u_char)'\263',
	(u_char)'\264', (u_char)'\265', (u_char)'\266', (u_char)'\267',
	(u_char)'\270', (u_char)'\271', (u_char)'\272', (u_char)'\273',
	(u_char)'\274', (u_char)'\275', (u_char)'\276', (u_char)'\277',
	(u_char)'\300', (u_char)'\341', (u_char)'\342', (u_char)'\343',
	(u_char)'\344', (u_char)'\345', (u_char)'\346', (u_char)'\347',
	(u_char)'\350', (u_char)'\351', (u_char)'\352', (u_char)'\353',
	(u_char)'\354', (u_char)'\355', (u_char)'\356', (u_char)'\357',
	(u_char)'\360', (u_char)'\361', (u_char)'\362', (u_char)'\363',
	(u_char)'\364', (u_char)'\365', (u_char)'\366', (u_char)'\367',
	(u_char)'\370', (u_char)'\371', (u_char)'\372', (u_char)'\333',
	(u_char)'\334', (u_char)'\335', (u_char)'\336', (u_char)'\337',
	(u_char)'\340', (u_char)'\341', (u_char)'\342', (u_char)'\343',
	(u_char)'\344', (u_char)'\345', (u_char)'\346', (u_char)'\347',
	(u_char)'\350', (u_char)'\351', (u_char)'\352', (u_char)'\353',
	(u_char)'\354', (u_char)'\355', (u_char)'\356', (u_char)'\357',
	(u_char)'\360', (u_char)'\361', (u_char)'\362', (u_char)'\363',
	(u_char)'\364', (u_char)'\365', (u_char)'\366', (u_char)'\367',
	(u_char)'\370', (u_char)'\371', (u_char)'\372', (u_char)'\373',
	(u_char)'\374', (u_char)'\375', (u_char)'\376', (u_char)'\377',
};

int
netsharkint_strcasecmp(const char *s1, const char *s2)
{
	register const u_char	*cm = charmap,
				*us1 = (const u_char *)s1,
				*us2 = (const u_char *)s2;

	while (cm[*us1] == cm[*us2++])
		if (*us1++ == '\0')
			return(0);
	return (cm[*us1] - cm[*--us2]);
}

struct dlt_choice {
	const char *name;
	const char *description;
	int	dlt;
};

#define DLT_CHOICE(code, description) { #code, description, DLT_ ## code }
#define DLT_CHOICE_SENTINEL { NULL, NULL, 0 }

static struct dlt_choice dlt_choices[] = {
	DLT_CHOICE(NULL, "BSD loopback"),
	DLT_CHOICE(EN10MB, "Ethernet"),
	DLT_CHOICE(RAW, "Raw IP"),
	DLT_CHOICE(LOOP, "OpenBSD loopback"),
	DLT_CHOICE(LINUX_SLL, "Linux cooked v1"),
	DLT_CHOICE(IEEE802_11, "802.11 WiFi"),
	DLT_CHOICE_SENTINEL
};

int
netshark_datalink_name_to_val(const char *name)
{
	int i;

	for (i = 0; dlt_choices[i].name != NULL; i++) {
		if (netsharkint_strcasecmp(dlt_choices[i].name, name) == 0)
			return (dlt_choices[i].dlt);
	}
	return (-1);
}

const char *
netshark_datalink_val_to_name(int dlt)
{
	int i;

	for (i = 0; dlt_choices[i].name != NULL; i++) {
		if (dlt_choices[i].dlt == dlt)
			return (dlt_choices[i].name);
	}
	return (NULL);
}

const char *
netshark_datalink_val_to_description(int dlt)
{
	int i;

	for (i = 0; dlt_choices[i].name != NULL; i++) {
		if (dlt_choices[i].dlt == dlt)
			return (dlt_choices[i].description);
	}
	return (NULL);
}

const char *
netshark_datalink_val_to_description_or_dlt(int dlt)
{
        static thread_local char unkbuf[40];
        const char *description;

        description = netshark_datalink_val_to_description(dlt);
        if (description != NULL) {
                return description;
        } else {
                (void)snprintf(unkbuf, sizeof(unkbuf), "DLT %d", dlt);
                return unkbuf;
        }
}

struct tstamp_type_choice {
	const char *name;
	const char *description;
	int	type;
};

static struct tstamp_type_choice tstamp_type_choices[] = {
	{ "host", "Host", NETSHARK_TSTAMP_HOST },
	{ "host_lowprec", "Host, low precision", NETSHARK_TSTAMP_HOST_LOWPREC },
	{ "host_hiprec", "Host, high precision", NETSHARK_TSTAMP_HOST_HIPREC },
	{ "adapter", "Adapter", NETSHARK_TSTAMP_ADAPTER },
	{ "adapter_unsynced", "Adapter, not synced with system time", NETSHARK_TSTAMP_ADAPTER_UNSYNCED },
	{ "host_hiprec_unsynced", "Host, high precision, not synced with system time", NETSHARK_TSTAMP_HOST_HIPREC_UNSYNCED },
	{ NULL, NULL, 0 }
};

int
netshark_tstamp_type_name_to_val(const char *name)
{
	int i;

	for (i = 0; tstamp_type_choices[i].name != NULL; i++) {
		if (netsharkint_strcasecmp(tstamp_type_choices[i].name, name) == 0)
			return (tstamp_type_choices[i].type);
	}
	return (NETSHARK_ERROR);
}

const char *
netshark_tstamp_type_val_to_name(int tstamp_type)
{
	int i;

	for (i = 0; tstamp_type_choices[i].name != NULL; i++) {
		if (tstamp_type_choices[i].type == tstamp_type)
			return (tstamp_type_choices[i].name);
	}
	return (NULL);
}

const char *
netshark_tstamp_type_val_to_description(int tstamp_type)
{
	int i;

	for (i = 0; tstamp_type_choices[i].name != NULL; i++) {
		if (tstamp_type_choices[i].type == tstamp_type)
			return (tstamp_type_choices[i].description);
	}
	return (NULL);
}

int
netshark_snapshot(netshark_t *p)
{
	if (!p->activated)
		return (NETSHARK_ERROR_NOT_ACTIVATED);
	return (p->snapshot);
}

int
netshark_is_swapped(netshark_t *p)
{
	if (!p->activated)
		return (NETSHARK_ERROR_NOT_ACTIVATED);
	return (p->swapped);
}

int
netshark_major_version(netshark_t *p)
{
	if (!p->activated)
		return (NETSHARK_ERROR_NOT_ACTIVATED);
	return (p->version_major);
}

int
netshark_minor_version(netshark_t *p)
{
	if (!p->activated)
		return (NETSHARK_ERROR_NOT_ACTIVATED);
	return (p->version_minor);
}

int
netshark_bufsize(netshark_t *p)
{
	if (!p->activated)
		return (NETSHARK_ERROR_NOT_ACTIVATED);
	return (p->bufsize);
}

FILE *
netshark_file(netshark_t *p)
{
	return (p->rfile);
}

#ifdef _WIN32
int
netshark_fileno(netshark_t *p)
{
	if (p->handle != INVALID_HANDLE_VALUE) {
		/*
		 * This is a bogus and now-deprecated API; we
		 * squelch the narrowing warning for the cast
		 * from HANDLE to intptr_t.  If Windows programmers
		 * need to get at the HANDLE for a netshark_t, *if*
		 * there is one, they should request such a
		 * routine (and be prepared for it to return
		 * INVALID_HANDLE_VALUE).
		 */
DIAG_OFF_NARROWING
		return ((int)(intptr_t)p->handle);
DIAG_ON_NARROWING
	} else
		return (NETSHARK_ERROR);
}
#else /* _WIN32 */
int
netshark_fileno(netshark_t *p)
{
	return (p->fd);
}
#endif /* _WIN32 */

#if !defined(_WIN32)
int
netshark_get_selectable_fd(netshark_t *p)
{
	return (p->selectable_fd);
}

const struct timeval *
netshark_get_required_select_timeout(netshark_t *p)
{
	return (p->required_select_timeout);
}
#endif

void
netshark_perror(netshark_t *p, const char *prefix)
{
	fprintf(stderr, "%s: %s\n", prefix, p->errbuf);
}

char *
netshark_geterr(netshark_t *p)
{
	return (p->errbuf);
}

int
netshark_getnonblock(netshark_t *p, char *errbuf)
{
	int ret;

	ret = p->getnonblock_op(p);
	if (ret == -1) {
		/*
		 * The get nonblock operation sets p->errbuf; this
		 * function *shouldn't* have had a separate errbuf
		 * argument, as it didn't need one, but I goofed
		 * when adding it.
		 *
		 * We copy the error message to errbuf, so callers
		 * can find it in either place.
		 */
		netsharkint_strlcpy(errbuf, p->errbuf, NETSHARK_ERRBUF_SIZE);
	}
	return (ret);
}

/*
 * Get the current non-blocking mode setting, under the assumption that
 * it's just the standard POSIX non-blocking flag.
 */
#if !defined(_WIN32)
int
netsharkint_getnonblock_fd(netshark_t *p)
{
	int fdflags;

	fdflags = fcntl(p->fd, F_GETFL, 0);
	if (fdflags == -1) {
		netsharkint_fmt_errmsg_for_errno(p->errbuf, NETSHARK_ERRBUF_SIZE,
		    errno, "F_GETFL");
		return (-1);
	}
	if (fdflags & O_NONBLOCK)
		return (1);
	else
		return (0);
}
#endif

int
netshark_setnonblock(netshark_t *p, int nonblock, char *errbuf)
{
	int ret;

	ret = p->setnonblock_op(p, nonblock);
	if (ret == -1) {
		/*
		 * The set nonblock operation sets p->errbuf; this
		 * function *shouldn't* have had a separate errbuf
		 * argument, as it didn't need one, but I goofed
		 * when adding it.
		 *
		 * We copy the error message to errbuf, so callers
		 * can find it in either place.
		 */
		netsharkint_strlcpy(errbuf, p->errbuf, NETSHARK_ERRBUF_SIZE);
	}
	return (ret);
}

#if !defined(_WIN32)
/*
 * Set non-blocking mode, under the assumption that it's just the
 * standard POSIX non-blocking flag.  (This can be called by the
 * per-platform non-blocking-mode routine if that routine also
 * needs to do some additional work.)
 */
int
netsharkint_setnonblock_fd(netshark_t *p, int nonblock)
{
	int fdflags;

	fdflags = fcntl(p->fd, F_GETFL, 0);
	if (fdflags == -1) {
		netsharkint_fmt_errmsg_for_errno(p->errbuf, NETSHARK_ERRBUF_SIZE,
		    errno, "F_GETFL");
		return (-1);
	}
	if (nonblock)
		fdflags |= O_NONBLOCK;
	else
		fdflags &= ~O_NONBLOCK;
	if (fcntl(p->fd, F_SETFL, fdflags) == -1) {
		netsharkint_fmt_errmsg_for_errno(p->errbuf, NETSHARK_ERRBUF_SIZE,
		    errno, "F_SETFL");
		return (-1);
	}
	return (0);
}
#endif

/*
 * Generate error strings for NETSHARK_ERROR_ and NETSHARK_WARNING_ values.
 */
const char *
netshark_statustostr(int errnum)
{
	static thread_local char ebuf[15+10+1];

	switch (errnum) {

	case NETSHARK_WARNING:
		return("Generic warning");

	case NETSHARK_WARNING_TSTAMP_TYPE_NOTSUP:
		return ("That type of time stamp is not supported by that device");

	case NETSHARK_WARNING_PROMISC_NOTSUP:
		return ("That device doesn't support promiscuous mode");

	case NETSHARK_ERROR:
		return("Generic error");

	case NETSHARK_ERROR_BREAK:
		return("Loop terminated by netshark_breakloop");

	case NETSHARK_ERROR_NOT_ACTIVATED:
		return("The netshark_t has not been activated");

	case NETSHARK_ERROR_ACTIVATED:
		return ("The setting can't be changed after the netshark_t is activated");

	case NETSHARK_ERROR_NO_SUCH_DEVICE:
		return ("No such device exists");

	case NETSHARK_ERROR_RFMON_NOTSUP:
		return ("That device doesn't support monitor mode");

	case NETSHARK_ERROR_NOT_RFMON:
		return ("That operation is supported only in monitor mode");

	case NETSHARK_ERROR_PERM_DENIED:
		return ("You don't have permission to perform this capture on that device");

	case NETSHARK_ERROR_IFACE_NOT_UP:
		return ("That device is not up");

	case NETSHARK_ERROR_CANTSET_TSTAMP_TYPE:
		return ("That device doesn't support setting the time stamp type");

	case NETSHARK_ERROR_PROMISC_PERM_DENIED:
		return ("You don't have permission to capture in promiscuous mode on that device");

	case NETSHARK_ERROR_TSTAMP_PRECISION_NOTSUP:
		return ("That device doesn't support that time stamp precision");

	case NETSHARK_ERROR_CAPTURE_NOTSUP:
		return ("Packet capture is not supported on that device");
	}
	(void)snprintf(ebuf, sizeof ebuf, "Unknown error: %d", errnum);
	return(ebuf);
}

/*
 * A long time ago the purpose of this function was to hide the difference
 * between those Unix-like OSes that implemented strerror() and those that
 * didn't.  All the currently supported OSes implement strerror(), which is in
 * POSIX.1-2001, uniformly and that particular problem no longer exists.  But
 * now they implement a few incompatible thread-safe variants of strerror(),
 * and hiding that difference is the current purpose of this function.
 */
const char *
netshark_strerror(int errnum)
{
#ifdef _WIN32
	static thread_local char errbuf[NETSHARK_ERRBUF_SIZE];
	errno_t err = strerror_s(errbuf, NETSHARK_ERRBUF_SIZE, errnum);

	if (err != 0) /* err = 0 if successful */
		netsharkint_strlcpy(errbuf, "strerror_s() error", NETSHARK_ERRBUF_SIZE);
	return (errbuf);
#elif defined(HAVE_GNU_STRERROR_R)
	/*
	 * We have a GNU-style strerror_r(), which is *not* guaranteed to
	 * do anything to the buffer handed to it, and which returns a
	 * pointer to the error string, which may or may not be in
	 * the buffer.
	 *
	 * It is, however, guaranteed to succeed.
	 *
	 * At the time of this writing this applies to the following cases,
	 * each of which allows to use either the GNU implementation or the
	 * POSIX implementation, and this source tree defines _GNU_SOURCE to
	 * use the GNU implementation:
	 * - Hurd
	 * - Linux with GNU libc
	 * - Linux with uClibc-ng
	 */
	static thread_local char errbuf[NETSHARK_ERRBUF_SIZE];
	return strerror_r(errnum, errbuf, NETSHARK_ERRBUF_SIZE);
#elif defined(HAVE_POSIX_STRERROR_R)
	/*
	 * We have a POSIX-style strerror_r(), which is guaranteed to fill
	 * in the buffer, but is not guaranteed to succeed.
	 *
	 * At the time of this writing this applies to the following cases:
	 * - AIX 7
	 * - FreeBSD
	 * - Haiku
	 * - HP-UX 11
	 * - illumos
	 * - Linux with musl libc
	 * - macOS
	 * - NetBSD
	 * - OpenBSD
	 * - Solaris 10 & 11
	 */
	static thread_local char errbuf[NETSHARK_ERRBUF_SIZE];
	int err = strerror_r(errnum, errbuf, NETSHARK_ERRBUF_SIZE);
	switch (err) {
	case 0:
		/* That worked. */
		break;

	case EINVAL:
		/*
		 * UNIX 03 says this isn't guaranteed to produce a
		 * fallback error message.
		 */
		snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
		         "Unknown error: %d", errnum);
		break;
	case ERANGE:
		/*
		 * UNIX 03 says this isn't guaranteed to produce a
		 * fallback error message.
		 */
		snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
		         "Message for error %d is too long", errnum);
		break;
	default:
		snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
		         "strerror_r(%d, ...) unexpectedly returned %d",
		         errnum, err);
	}
	return errbuf;
#else
	/*
	 * At the time of this writing every supported OS implements strerror()
	 * and at least one thread-safe variant thereof, so this is a very
	 * unlikely last-resort branch.  Particular implementations of strerror()
	 * may be thread-safe, but this is neither required nor guaranteed.
	 */
	return (strerror(errnum));
#endif /* _WIN32 */
}

int
netshark_setfilter(netshark_t *p, struct bpf_program *fp)
{
	return (p->setfilter_op(p, fp));
}

/*
 * Set direction flag, which controls whether we accept only incoming
 * packets, only outgoing packets, or both.
 * Note that, depending on the platform, some or all direction arguments
 * might not be supported.
 */
int
netshark_setdirection(netshark_t *p, netshark_direction_t d)
{
	if (p->setdirection_op == NULL) {
		snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
		    "Setting direction is not supported on this device");
		return (-1);
	} else {
		switch (d) {

		case NETSHARK_D_IN:
		case NETSHARK_D_OUT:
		case NETSHARK_D_INOUT:
			/*
			 * Valid direction.
			 */
			return (p->setdirection_op(p, d));

		default:
			/*
			 * Invalid direction.
			 */
			snprintf(p->errbuf, sizeof(p->errbuf),
			    "Invalid direction");
			return (-1);
		}
	}
}

int
netshark_stats(netshark_t *p, struct netshark_stat *ps)
{
	return (p->stats_op(p, ps));
}

#ifdef _WIN32
struct netshark_stat *
netshark_stats_ex(netshark_t *p, int *netshark_stat_size)
{
	return (p->stats_ex_op(p, netshark_stat_size));
}

int
netshark_setbuff(netshark_t *p, int dim)
{
	return (p->setbuff_op(p, dim));
}

int
netshark_setmode(netshark_t *p, int mode)
{
	return (p->setmode_op(p, mode));
}

int
netshark_setmintocopy(netshark_t *p, int size)
{
	return (p->setmintocopy_op(p, size));
}

HANDLE
netshark_getevent(netshark_t *p)
{
	return (p->getevent_op(p));
}

int
netshark_oid_get_request(netshark_t *p, bpf_u_int32 oid, void *data, size_t *lenp)
{
	return (p->oid_get_request_op(p, oid, data, lenp));
}

int
netshark_oid_set_request(netshark_t *p, bpf_u_int32 oid, const void *data, size_t *lenp)
{
	return (p->oid_set_request_op(p, oid, data, lenp));
}

netshark_send_queue *
netshark_sendqueue_alloc(u_int memsize)
{
	netshark_send_queue *tqueue;

	/* Allocate the queue */
	tqueue = (netshark_send_queue *)malloc(sizeof(netshark_send_queue));
	if (tqueue == NULL){
		return (NULL);
	}

	/* Allocate the buffer */
	tqueue->buffer = (char *)malloc(memsize);
	if (tqueue->buffer == NULL) {
		free(tqueue);
		return (NULL);
	}

	tqueue->maxlen = memsize;
	tqueue->len = 0;

	return (tqueue);
}

void
netshark_sendqueue_destroy(netshark_send_queue *queue)
{
	free(queue->buffer);
	free(queue);
}

int
netshark_sendqueue_queue(netshark_send_queue *queue, const struct netshark_pkthdr *pkt_header, const u_char *pkt_data)
{
	if (queue->len + sizeof(struct netshark_pkthdr) + pkt_header->caplen > queue->maxlen){
		return (-1);
	}

	/* Copy the netshark_pkthdr header*/
	memcpy(queue->buffer + queue->len, pkt_header, sizeof(struct netshark_pkthdr));
	queue->len += sizeof(struct netshark_pkthdr);

	/* copy the packet */
	memcpy(queue->buffer + queue->len, pkt_data, pkt_header->caplen);
	queue->len += pkt_header->caplen;

	return (0);
}

u_int
netshark_sendqueue_transmit(netshark_t *p, netshark_send_queue *queue, int sync)
{
	return (p->sendqueue_transmit_op(p, queue, sync));
}

int
netshark_setuserbuffer(netshark_t *p, int size)
{
	return (p->setuserbuffer_op(p, size));
}

int
netshark_live_dump(netshark_t *p, char *filename, int maxsize, int maxpacks)
{
	return (p->live_dump_op(p, filename, maxsize, maxpacks));
}

int
netshark_live_dump_ended(netshark_t *p, int sync)
{
	return (p->live_dump_ended_op(p, sync));
}

PAirnetsharkHandle
netshark_get_airnetshark_handle(netshark_t *p)
{
	(void)snprintf(p->errbuf, sizeof(p->errbuf),
		"AirPcap devices are no longer supported");

	return (NULL);
}
#endif

/*
 * On some platforms, we need to clean up promiscuous or monitor mode
 * when we close a device - and we want that to happen even if the
 * application just exits without explicitly closing devices.
 * On those platforms, we need to register a "close all the netsharks"
 * routine to be called when we exit, and need to maintain a list of
 * netsharks that need to be closed to clean up modes.
 *
 * XXX - not thread-safe.
 */

/*
 * List of netsharks on which we've done something that needs to be
 * cleaned up.
 * If there are any such netsharks, we arrange to call "netshark_close_all()"
 * when we exit, and have it close all of them.
 */
static struct netshark *netsharks_to_close;

/*
 * TRUE if we've already called "atexit()" to cause "netshark_close_all()" to
 * be called on exit.
 */
static int did_atexit;

static void
netshark_close_all(void)
{
	struct netshark *handle;

	while ((handle = netsharks_to_close) != NULL) {
		netshark_close(handle);

		/*
		 * If a netshark module adds a netshark_t to the "close all"
		 * list by calling netsharkint_add_to_netsharks_to_close(), it
		 * must have a cleanup routine that removes it from the
		 * list, by calling netsharkint_remove_from_netsharks_to_close(),
		 * and must make that cleanup routine the cleanup_op
		 * for the netshark_t.
		 *
		 * That means that, after netshark_close() - which calls
		 * the cleanup_op for the netshark_t - the netshark_t must
		 * have been removed from the list, so netsharks_to_close
		 * must not be equal to handle.
		 *
		 * We check for that, and abort if handle is still
		 * at the head of the list, to prevent infinite loops.
		 */
		if (netsharks_to_close == handle)
			abort();
	}
}

int
netsharkint_do_addexit(netshark_t *p)
{
	/*
	 * If we haven't already done so, arrange to have
	 * "netshark_close_all()" called when we exit.
	 */
	if (!did_atexit) {
		if (atexit(netshark_close_all) != 0) {
			/*
			 * "atexit()" failed; let our caller know.
			 */
			netsharkint_strlcpy(p->errbuf, "atexit failed", NETSHARK_ERRBUF_SIZE);
			return (0);
		}
		did_atexit = 1;
	}
	return (1);
}

void
netsharkint_add_to_netsharks_to_close(netshark_t *p)
{
	p->next = netsharks_to_close;
	netsharks_to_close = p;
}

void
netsharkint_remove_from_netsharks_to_close(netshark_t *p)
{
	netshark_t *pc, *prevpc;

	for (pc = netsharks_to_close, prevpc = NULL; pc != NULL;
	    prevpc = pc, pc = pc->next) {
		if (pc == p) {
			/*
			 * Found it.  Remove it from the list.
			 */
			if (prevpc == NULL) {
				/*
				 * It was at the head of the list.
				 */
				netsharks_to_close = pc->next;
			} else {
				/*
				 * It was in the middle of the list.
				 */
				prevpc->next = pc->next;
			}
			break;
		}
	}
}

void
netsharkint_breakloop_common(netshark_t *p)
{
	p->break_loop = 1;
}


void
netsharkint_cleanup_live_common(netshark_t *p)
{
	if (p->opt.device != NULL) {
		free(p->opt.device);
		p->opt.device = NULL;
	}
	if (p->buffer != NULL) {
		free(p->buffer);
		p->buffer = NULL;
	}
	if (p->dlt_list != NULL) {
		free(p->dlt_list);
		p->dlt_list = NULL;
		p->dlt_count = 0;
	}
	if (p->tstamp_type_list != NULL) {
		free(p->tstamp_type_list);
		p->tstamp_type_list = NULL;
		p->tstamp_type_count = 0;
	}
	if (p->tstamp_precision_list != NULL) {
		free(p->tstamp_precision_list);
		p->tstamp_precision_list = NULL;
		p->tstamp_precision_count = 0;
	}
	netshark_freecode(&p->fcode);
#if !defined(_WIN32)
	if (p->fd >= 0) {
		close(p->fd);
		p->fd = -1;
	}
	p->selectable_fd = -1;
#endif
}

/*
 * API compatible with WinPcap's "send a packet" routine - returns -1
 * on error, 0 otherwise.
 *
 * XXX - what if we get a short write?
 */
int
netshark_sendpacket(netshark_t *p, const u_char *buf, int size)
{
	if (size <= 0) {
		netsharkint_fmt_errmsg_for_errno(p->errbuf, NETSHARK_ERRBUF_SIZE,
		    errno, "The number of bytes to be sent must be positive");
		return (NETSHARK_ERROR);
	}

	if (p->inject_op(p, buf, size) == -1)
		return (-1);
	return (0);
}

/*
 * API compatible with OpenBSD's "send a packet" routine - returns -1 on
 * error, number of bytes written otherwise.
 */
int
netshark_inject(netshark_t *p, const void *buf, size_t size)
{
	/*
	 * We return the number of bytes written, so the number of
	 * bytes to write must fit in an int.
	 */
	if (size > INT_MAX) {
		netsharkint_fmt_errmsg_for_errno(p->errbuf, NETSHARK_ERRBUF_SIZE,
		    errno, "More than %d bytes cannot be injected", INT_MAX);
		return (NETSHARK_ERROR);
	}

	if (size == 0) {
		netsharkint_fmt_errmsg_for_errno(p->errbuf, NETSHARK_ERRBUF_SIZE,
		    errno, "The number of bytes to be injected must not be zero");
		return (NETSHARK_ERROR);
	}

	return (p->inject_op(p, buf, (int)size));
}

void
netshark_close(netshark_t *p)
{
	p->cleanup_op(p);
	free(p);
}

/*
 * Helpers for safely loading code at run time.
 * Currently Windows-only.
 */
#ifdef _WIN32
//
// This wrapper around loadlibrary appends the system folder (usually
// C:\Windows\System32) to the relative path of the DLL, so that the DLL
// is always loaded from an absolute path (it's no longer possible to
// load modules from the application folder).
// This solves the DLL Hijacking issue discovered in August 2010:
//
// https://blog.rapid7.com/2010/08/23/exploiting-dll-hijacking-flaws/
// https://blog.rapid7.com/2010/08/23/application-dll-load-hijacking/
// (the purported Rapid7 blog post link in the first of those two links
// is broken; the second of those links works.)
//
// If any links there are broken from all the content shuffling Rapid&
// did, see archived versions of the posts at their original homes, at
//
// https://web.archive.org/web/20110122175058/http://blog.metasploit.com/2010/08/exploiting-dll-hijacking-flaws.html
// https://web.archive.org/web/20100828112111/http://blog.rapid7.com/?p=5325
//
netshark_code_handle_t
netsharkint_load_code(const char *name)
{
	/*
	 * XXX - should this work in UTF-16LE rather than in the local
	 * ANSI code page?
	 */
	CHAR path[MAX_PATH];
	CHAR fullFileName[MAX_PATH];
	UINT res;
	HMODULE hModule = NULL;

	do
	{
		res = GetSystemDirectoryA(path, MAX_PATH);

		if (res == 0) {
			//
			// some bad failure occurred;
			//
			break;
		}

		if (res > MAX_PATH) {
			//
			// the buffer was not big enough
			//
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			break;
		}

		if (res + 1 + strlen(name) + 1 < MAX_PATH) {
			memcpy(fullFileName, path, res * sizeof(TCHAR));
			fullFileName[res] = '\\';
			memcpy(&fullFileName[res + 1], name, (strlen(name) + 1) * sizeof(TCHAR));

			hModule = LoadLibraryA(fullFileName);
		} else
			SetLastError(ERROR_INSUFFICIENT_BUFFER);

	} while(FALSE);

	return hModule;
}

/*
 * Casting from FARPROC, which is the type of the return value of
 * GetProcAddress(), to a function pointer gets a C4191 warning
 * from Visual Studio 2022.
 *
 * Casting FARPROC to void * and returning the result, and then
 * casting the void * to a function pointer, doesn't get the
 * same warning.
 *
 * Given that, and given that the equivalent UN*X API, dlsym(),
 * returns a void *, we have netsharkint_find_function() return
 * a void *.
 */
void *
netsharkint_find_function(netshark_code_handle_t code, const char *func)
{
	return ((void *)GetProcAddress(code, func));
}
#endif

/*
 * Given a BPF program, a netshark_pkthdr structure for a packet, and the raw
 * data for the packet, check whether the packet passes the filter.
 * Returns the return value of the filter program, which will be zero if
 * the packet doesn't pass and non-zero if the packet does pass.
 */
int
netshark_offline_filter(const struct bpf_program *fp, const struct netshark_pkthdr *h,
    const u_char *pkt)
{
	const struct bpf_insn *fcode = fp->bf_insns;

	if (fcode != NULL)
		return (netsharkint_filter(fcode, pkt, h->len, h->caplen));
	else
		return (0);
}

static int
netshark_can_set_rfmon_dead(netshark_t *p)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "Rfmon mode doesn't apply on a netshark_open_dead netshark_t");
	return (NETSHARK_ERROR);
}

static int
netshark_read_dead(netshark_t *p, int cnt _U_, netshark_handler callback _U_,
    u_char *user _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "Packets aren't available from a netshark_open_dead netshark_t");
	return (-1);
}

static void
netshark_breakloop_dead(netshark_t *p _U_)
{
	/*
	 * A "dead" netshark_t is just a placeholder to use in order to
	 * compile a filter to BPF code or to open a savefile for
	 * writing.  It doesn't support any operations, including
	 * capturing or reading packets, so there will never be a
	 * get-packets loop in progress to break out *of*.
	 *
	 * As such, this routine doesn't need to do anything.
	 */
}

static int
netshark_inject_dead(netshark_t *p, const void *buf _U_, int size _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "Packets can't be sent on a netshark_open_dead netshark_t");
	return (-1);
}

static int
netshark_setfilter_dead(netshark_t *p, struct bpf_program *fp _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "A filter cannot be set on a netshark_open_dead netshark_t");
	return (-1);
}

static int
netshark_setdirection_dead(netshark_t *p, netshark_direction_t d _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "The packet direction cannot be set on a netshark_open_dead netshark_t");
	return (-1);
}

static int
netshark_set_datalink_dead(netshark_t *p, int dlt _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "The link-layer header type cannot be set on a netshark_open_dead netshark_t");
	return (-1);
}

static int
netshark_getnonblock_dead(netshark_t *p)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "A netshark_open_dead netshark_t does not have a non-blocking mode setting");
	return (-1);
}

static int
netshark_setnonblock_dead(netshark_t *p, int nonblock _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "A netshark_open_dead netshark_t does not have a non-blocking mode setting");
	return (-1);
}

static int
netshark_stats_dead(netshark_t *p, struct netshark_stat *ps _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "Statistics aren't available from a netshark_open_dead netshark_t");
	return (-1);
}

#ifdef _WIN32
static struct netshark_stat *
netshark_stats_ex_dead(netshark_t *p, int *netshark_stat_size _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "Statistics aren't available from a netshark_open_dead netshark_t");
	return (NULL);
}

static int
netshark_setbuff_dead(netshark_t *p, int dim _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "The kernel buffer size cannot be set on a netshark_open_dead netshark_t");
	return (-1);
}

static int
netshark_setmode_dead(netshark_t *p, int mode _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "impossible to set mode on a netshark_open_dead netshark_t");
	return (-1);
}

static int
netshark_setmintocopy_dead(netshark_t *p, int size _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "The mintocopy parameter cannot be set on a netshark_open_dead netshark_t");
	return (-1);
}

static HANDLE
netshark_getevent_dead(netshark_t *p)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "A netshark_open_dead netshark_t has no event handle");
	return (INVALID_HANDLE_VALUE);
}

static int
netshark_oid_get_request_dead(netshark_t *p, bpf_u_int32 oid _U_, void *data _U_,
    size_t *lenp _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "An OID get request cannot be performed on a netshark_open_dead netshark_t");
	return (NETSHARK_ERROR);
}

static int
netshark_oid_set_request_dead(netshark_t *p, bpf_u_int32 oid _U_, const void *data _U_,
    size_t *lenp _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "An OID set request cannot be performed on a netshark_open_dead netshark_t");
	return (NETSHARK_ERROR);
}

static u_int
netshark_sendqueue_transmit_dead(netshark_t *p, netshark_send_queue *queue _U_,
    int sync _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "Packets cannot be transmitted on a netshark_open_dead netshark_t");
	return (0);
}

static int
netshark_setuserbuffer_dead(netshark_t *p, int size _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "The user buffer cannot be set on a netshark_open_dead netshark_t");
	return (-1);
}

static int
netshark_live_dump_dead(netshark_t *p, char *filename _U_, int maxsize _U_,
    int maxpacks _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "Live packet dumping cannot be performed on a netshark_open_dead netshark_t");
	return (-1);
}

static int
netshark_live_dump_ended_dead(netshark_t *p, int sync _U_)
{
	snprintf(p->errbuf, NETSHARK_ERRBUF_SIZE,
	    "Live packet dumping cannot be performed on a netshark_open_dead netshark_t");
	return (-1);
}
#endif /* _WIN32 */

static void
netshark_cleanup_dead(netshark_t *p _U_)
{
	/* Nothing to do. */
}

netshark_t *
netshark_open_dead_with_tstamp_precision(int linktype, int snaplen, u_int precision)
{
	netshark_t *p;

	switch (precision) {

	case NETSHARK_TSTAMP_PRECISION_MICRO:
	case NETSHARK_TSTAMP_PRECISION_NANO:
		break;

	default:
		/*
		 * This doesn't really matter, but we don't have any way
		 * to report particular errors, so the only failure we
		 * should have is a memory allocation failure.  Just
		 * pick microsecond precision.
		 */
		precision = NETSHARK_TSTAMP_PRECISION_MICRO;
		break;
	}
	p = malloc(sizeof(*p));
	if (p == NULL)
		return NULL;
	memset (p, 0, sizeof(*p));
	p->snapshot = snaplen;
	p->linktype = linktype;
	p->opt.tstamp_precision = precision;
	p->can_set_rfmon_op = netshark_can_set_rfmon_dead;
	p->read_op = netshark_read_dead;
	p->inject_op = netshark_inject_dead;
	p->setfilter_op = netshark_setfilter_dead;
	p->setdirection_op = netshark_setdirection_dead;
	p->set_datalink_op = netshark_set_datalink_dead;
	p->getnonblock_op = netshark_getnonblock_dead;
	p->setnonblock_op = netshark_setnonblock_dead;
	p->stats_op = netshark_stats_dead;
#ifdef _WIN32
	p->stats_ex_op = netshark_stats_ex_dead;
	p->setbuff_op = netshark_setbuff_dead;
	p->setmode_op = netshark_setmode_dead;
	p->setmintocopy_op = netshark_setmintocopy_dead;
	p->getevent_op = netshark_getevent_dead;
	p->oid_get_request_op = netshark_oid_get_request_dead;
	p->oid_set_request_op = netshark_oid_set_request_dead;
	p->sendqueue_transmit_op = netshark_sendqueue_transmit_dead;
	p->setuserbuffer_op = netshark_setuserbuffer_dead;
	p->live_dump_op = netshark_live_dump_dead;
	p->live_dump_ended_op = netshark_live_dump_ended_dead;
#endif
	p->breakloop_op = netshark_breakloop_dead;
	p->cleanup_op = netshark_cleanup_dead;

	/*
	 * A "dead" netshark_t never requires special BPF code generation.
	 */
	p->bpf_codegen_flags = 0;

	p->activated = 1;
	return (p);
}

netshark_t *
netshark_open_dead(int linktype, int snaplen)
{
	return (netshark_open_dead_with_tstamp_precision(linktype, snaplen,
	    NETSHARK_TSTAMP_PRECISION_MICRO));
}

#ifdef YYDEBUG
/*
 * Set the internal "debug printout" flag for the filter expression parser.
 * The code to print that stuff is present only if YYDEBUG is defined, so
 * the flag, and the routine to set it, are defined only if YYDEBUG is
 * defined.
 *
 * This is intended for libnetshark developers, not for general use.
 * If you want to set these in a program, you'll have to declare this
 * routine yourself, with the appropriate DLL import attribute on Windows;
 * it's not declared in any header file, and won't be declared in any
 * header file provided by libnetshark.
 */
NETSHARK_API void netshark_set_parser_debug(int value);

NETSHARK_API_DEF void
netshark_set_parser_debug(int value)
{
	netshark_debug = value;
}
#endif

/*
 * APIs.added in WinPcap for remote capture.
 *
 * Copyright (c) 2002 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2008 CACE Technologies, Davis (California)
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
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
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
#ifndef _WIN32
#include <dirent.h>		// for readdir
#endif

/* String identifier to be used in the netshark_findalldevs_ex() */
#define NETSHARK_TEXT_SOURCE_FILE "File"
#define NETSHARK_TEXT_SOURCE_FILE_LEN (sizeof NETSHARK_TEXT_SOURCE_FILE - 1)
/* String identifier to be used in the netshark_findalldevs_ex() */
#define NETSHARK_TEXT_SOURCE_ADAPTER "Network adapter"
#define NETSHARK_TEXT_SOURCE_ADAPTER_LEN (sizeof "Network adapter" - 1)

/* String identifier to be used in the netshark_findalldevs_ex() */
#define NETSHARK_TEXT_SOURCE_ON_LOCAL_HOST "on local host"
#define NETSHARK_TEXT_SOURCE_ON_LOCAL_HOST_LEN (sizeof NETSHARK_TEXT_SOURCE_ON_LOCAL_HOST + 1)

#ifdef ENABLE_REMOTE
 #define _USED_FOR_REMOTE
#else
 #define _USED_FOR_REMOTE _U_
#endif

int
netshark_findalldevs_ex(const char *source, struct netshark_rmtauth *auth _USED_FOR_REMOTE,
    netshark_if_t **alldevs, char *errbuf)
{
	int type;
	char name[NETSHARK_BUF_SIZE], path[NETSHARK_BUF_SIZE], filename[NETSHARK_BUF_SIZE];
	size_t pathlen;
	size_t stringlen;
	netshark_t *fp;
	char tmpstring[NETSHARK_BUF_SIZE + 1];		/* Needed to convert names and descriptions from 'old' syntax to the 'new' one */
	netshark_if_t *lastdev;	/* Last device in the netshark_if_t list */
	netshark_if_t *dev;		/* Device we're adding to the netshark_if_t list */

	/* List starts out empty. */
	(*alldevs) = NULL;
	lastdev = NULL;

	if (strlen(source) > NETSHARK_BUF_SIZE) {
		snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
		    "The source string is too long. Cannot handle it correctly.");
		return (NETSHARK_ERROR);
	}

	/*
	 * Determine the type of the source (file, local, remote).
	 *
	 * There are some differences if netshark_findalldevs_ex() is called to
	 * list files and remote adapters.
	 *
	 * In the first case, the name of the directory we have to look into
	 * must be present (therefore the 'name' parameter of the
	 * netshark_parsesrcstr() is present).
	 *
	 * In the second case, the name of the adapter is not required
	 * (we need just the host). So, we have to use this function a
	 * first time to get the source type, and a second time to get
	 * the appropriate info, which depends on the source type.
	 */
	if (netshark_parsesrcstr(source, &type, NULL, NULL, NULL, errbuf) == -1)
		return (NETSHARK_ERROR);

	switch (type) {

	case NETSHARK_SRC_IFLOCAL:
		if (netshark_parsesrcstr(source, &type, NULL, NULL, NULL, errbuf) == -1)
			return (NETSHARK_ERROR);

		/* Initialize temporary string */
		tmpstring[NETSHARK_BUF_SIZE] = 0;

		/* The user wants to retrieve adapters from a local host */
		if (netshark_findalldevs(alldevs, errbuf) == -1)
			return (NETSHARK_ERROR);

		if (*alldevs == NULL) {
			snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
			    "No interfaces found! Make sure libnetshark/Nnetshark is properly installed"
			    " on the local machine.");
			return (NETSHARK_ERROR);
		}

		/*
		 * Scan all the interfaces and modify name and description.
		 *
		 * This is a trick in order to avoid the re-implementation
		 * of netshark_findalldevs here.
		 */
		dev = *alldevs;
		while (dev) {
			char *localdesc, *desc;

			/* Create the new device identifier */
			if (netshark_createsrcstr(tmpstring, NETSHARK_SRC_IFLOCAL, NULL, NULL, dev->name, errbuf) == -1)
				return (NETSHARK_ERROR);

			/* Delete the old pointer */
			free(dev->name);

			/* Make a copy of the new device identifier */
			dev->name = strdup(tmpstring);
			if (dev->name == NULL) {
				netsharkint_fmt_errmsg_for_errno(errbuf,
				    NETSHARK_ERRBUF_SIZE, errno,
				    "malloc() failed");
				netshark_freealldevs(*alldevs);
				return (NETSHARK_ERROR);
			}

			/*
			 * Create the description.
			 */
			if ((dev->description == NULL) ||
			    (dev->description[0] == 0))
				localdesc = dev->name;
			else
				localdesc = dev->description;
			if (netsharkint_asprintf(&desc, "%s '%s' %s",
			    NETSHARK_TEXT_SOURCE_ADAPTER, localdesc,
			    NETSHARK_TEXT_SOURCE_ON_LOCAL_HOST) == -1) {
				netsharkint_fmt_errmsg_for_errno(errbuf,
				    NETSHARK_ERRBUF_SIZE, errno,
				    "malloc() failed");
				netshark_freealldevs(*alldevs);
				return (NETSHARK_ERROR);
			}

			/* Now overwrite the description */
			free(dev->description);
			dev->description = desc;

			dev = dev->next;
		}

		return (0);

	case NETSHARK_SRC_FILE:
	{
#ifdef _WIN32
		WIN32_FIND_DATA filedata;
		HANDLE filehandle;
#else
		struct dirent *filedata;
		DIR *unixdir;
#endif

		if (netshark_parsesrcstr(source, &type, NULL, NULL, name, errbuf) == -1)
			return (NETSHARK_ERROR);

		/* Check that the filename is correct */
		stringlen = strlen(name);

		/*
		 * The directory must end with '\' in Windows and
		 * '/' in UN*Xes.
		 */
#ifdef _WIN32
#define ENDING_CHAR '\\'
#else
#define ENDING_CHAR '/'
#endif

		if (name[stringlen - 1] != ENDING_CHAR) {
			name[stringlen] = ENDING_CHAR;
			name[stringlen + 1] = 0;

			stringlen++;
		}

		/* Save the path for future reference */
		snprintf(path, sizeof(path), "%s", name);
		pathlen = strlen(path);

#ifdef _WIN32
		/*
		 * To perform directory listing, Windows must have an
		 * asterisk as the ending character.
		 */
		if (name[stringlen - 1] != '*')	{
			name[stringlen] = '*';
			name[stringlen + 1] = 0;
		}

		filehandle = FindFirstFile(name, &filedata);

		if (filehandle == INVALID_HANDLE_VALUE) {
			snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
			    "Error when listing files: does folder '%s' exist?", path);
			return (NETSHARK_ERROR);
		}

#else
		/* opening the folder */
		unixdir= opendir(path);
		if (unixdir == NULL) {
			DIAG_OFF_FORMAT_TRUNCATION
			snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
			    "Error when listing files in '%s': %s", path, netshark_strerror(errno));
			DIAG_ON_FORMAT_TRUNCATION
			return (NETSHARK_ERROR);
		}

		/* get the first file into it */
		errno = 0;
		filedata= readdir(unixdir);

		if (filedata == NULL) {
			DIAG_OFF_FORMAT_TRUNCATION
			snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
			    "Error when listing files in '%s': %s", path, netshark_strerror(errno));
			DIAG_ON_FORMAT_TRUNCATION
			closedir(unixdir);
			return (NETSHARK_ERROR);
		}
#endif

		/* Add all files we find to the list. */
		do {
#ifdef _WIN32
			/* Skip the file if the pathname won't fit in the buffer */
			if (pathlen + strlen(filedata.cFileName) >= sizeof(filename))
				continue;
			snprintf(filename, sizeof(filename), "%s%s", path, filedata.cFileName);
#else
			if (pathlen + strlen(filedata->d_name) >= sizeof(filename))
				continue;
			DIAG_OFF_FORMAT_TRUNCATION
			snprintf(filename, sizeof(filename), "%s%s", path, filedata->d_name);
			DIAG_ON_FORMAT_TRUNCATION
#endif

			fp = netshark_open_offline(filename, errbuf);

			if (fp) {
				/* allocate the main structure */
				dev = (netshark_if_t *)malloc(sizeof(netshark_if_t));
				if (dev == NULL) {
					netsharkint_fmt_errmsg_for_errno(errbuf,
					    NETSHARK_ERRBUF_SIZE, errno,
					    "malloc() failed");
					netshark_freealldevs(*alldevs);
#ifdef _WIN32
					FindClose(filehandle);
#else
					closedir(unixdir);
#endif
					return (NETSHARK_ERROR);
				}

				/* Initialize the structure to 'zero' */
				memset(dev, 0, sizeof(netshark_if_t));

				/* Append it to the list. */
				if (lastdev == NULL) {
					/*
					 * List is empty, so it's also
					 * the first device.
					 */
					*alldevs = dev;
				} else {
					/*
					 * Append after the last device.
					 */
					lastdev->next = dev;
				}
				/* It's now the last device. */
				lastdev = dev;

				/* Create the new source identifier */
				if (netshark_createsrcstr(tmpstring, NETSHARK_SRC_FILE,
				    NULL, NULL, filename, errbuf) == -1) {
					netshark_freealldevs(*alldevs);
#ifdef _WIN32
					FindClose(filehandle);
#else
					closedir(unixdir);
#endif
					return (NETSHARK_ERROR);
				}

				dev->name = strdup(tmpstring);
				if (dev->name == NULL) {
					netsharkint_fmt_errmsg_for_errno(errbuf,
					    NETSHARK_ERRBUF_SIZE, errno,
					    "malloc() failed");
					netshark_freealldevs(*alldevs);
#ifdef _WIN32
					FindClose(filehandle);
#else
					closedir(unixdir);
#endif
					return (NETSHARK_ERROR);
				}

				/*
				 * Create the description.
				 */
				if (netsharkint_asprintf(&dev->description,
				    "%s '%s' %s", NETSHARK_TEXT_SOURCE_FILE,
				    filename, NETSHARK_TEXT_SOURCE_ON_LOCAL_HOST) == -1) {
					netsharkint_fmt_errmsg_for_errno(errbuf,
					    NETSHARK_ERRBUF_SIZE, errno,
					    "malloc() failed");
					netshark_freealldevs(*alldevs);
#ifdef _WIN32
					FindClose(filehandle);
#else
					closedir(unixdir);
#endif
					return (NETSHARK_ERROR);
				}

				netshark_close(fp);
			}
		}
#ifdef _WIN32
		while (FindNextFile(filehandle, &filedata) != 0);
#else
		while ( (filedata= readdir(unixdir)) != NULL);
#endif


		/* Close the search handle. */
#ifdef _WIN32
		FindClose(filehandle);
#else
		closedir(unixdir);
#endif

		return (0);
	}

	case NETSHARK_SRC_IFREMOTE:
#ifdef ENABLE_REMOTE
		return (netshark_findalldevs_ex_remote(source, auth, alldevs, errbuf));
#else
		netsharkint_strlcpy(errbuf, "Remote packet capture is not supported",
		    NETSHARK_ERRBUF_SIZE);
		return (NETSHARK_ERROR);
#endif

	default:
		netsharkint_strlcpy(errbuf, "Source type not supported", NETSHARK_ERRBUF_SIZE);
		return (NETSHARK_ERROR);
	}
}

netshark_t *
netshark_open(const char *source, int snaplen, int flags, int read_timeout,
    struct netshark_rmtauth *auth _USED_FOR_REMOTE, char *errbuf)
{
	char name[NETSHARK_BUF_SIZE];
	int type;
	netshark_t *fp;
	int status;

	/*
	 * A null device name is equivalent to the "any" device -
	 * which might not be supported on this platform, but
	 * this means that you'll get a "not supported" error
	 * rather than, say, a crash when we try to dereference
	 * the null pointer.
	 */
	if (source == NULL)
		source = "any";

	if (strlen(source) > NETSHARK_BUF_SIZE) {
		snprintf(errbuf, NETSHARK_ERRBUF_SIZE,
		    "The source string is too long. Cannot handle it correctly.");
		return (NULL);
	}

	/*
	 * Determine the type of the source (file, local, remote) and,
	 * if it's file or local, the name of the file or capture device.
	 */
	if (netshark_parsesrcstr(source, &type, NULL, NULL, name, errbuf) == -1)
		return (NULL);

	switch (type) {

	case NETSHARK_SRC_FILE:
		return (netshark_open_offline(name, errbuf));

	case NETSHARK_SRC_IFLOCAL:
		fp = netshark_create(name, errbuf);
		break;

	case NETSHARK_SRC_IFREMOTE:
#ifdef ENABLE_REMOTE
		/*
		 * Although we already have host, port and iface, we prefer
		 * to pass only 'source' to netshark_open_rnetshark(), so that it
		 * has to call netshark_parsesrcstr() again.
		 * This is less optimized, but much clearer.
		 */
		return (netshark_open_rnetshark(source, snaplen, flags, read_timeout,
		    auth, errbuf));
#else
		netsharkint_strlcpy(errbuf, "Remote packet capture is not supported",
		    NETSHARK_ERRBUF_SIZE);
		return (NULL);
#endif

	default:
		netsharkint_strlcpy(errbuf, "Source type not supported",
		    NETSHARK_ERRBUF_SIZE);
		return (NULL);
	}

	if (fp == NULL)
		return (NULL);
	status = netshark_set_snaplen(fp, snaplen);
	if (status < 0)
		goto fail;
	if (flags & NETSHARK_OPENFLAG_PROMISCUOUS) {
		status = netshark_set_promisc(fp, 1);
		if (status < 0)
			goto fail;
	}
	if (flags & NETSHARK_OPENFLAG_MAX_RESPONSIVENESS) {
		status = netshark_set_immediate_mode(fp, 1);
		if (status < 0)
			goto fail;
	}
#ifdef _WIN32
	/*
	 * This flag is supported on Windows only.
	 * XXX - is there a way to support it with
	 * the capture mechanisms on UN*X?  It's not
	 * exactly a "set direction" operation; I
	 * think it means "do not capture packets
	 * injected with netshark_sendpacket() or
	 * netshark_inject()".
	 */
	/* disable loopback capture if requested */
	if (flags & NETSHARK_OPENFLAG_NOCAPTURE_LOCAL)
		fp->opt.nocapture_local = 1;
#endif /* _WIN32 */
	status = netshark_set_timeout(fp, read_timeout);
	if (status < 0)
		goto fail;
	status = netshark_activate(fp);
	if (status < 0)
		goto fail;
	return fp;

fail:
	DIAG_OFF_FORMAT_TRUNCATION
	if (status == NETSHARK_ERROR)
		snprintf(errbuf, NETSHARK_ERRBUF_SIZE, "%s: %s",
		    name, fp->errbuf);
	else if (status == NETSHARK_ERROR_NO_SUCH_DEVICE ||
	    status == NETSHARK_ERROR_PERM_DENIED ||
	    status == NETSHARK_ERROR_PROMISC_PERM_DENIED)
		snprintf(errbuf, NETSHARK_ERRBUF_SIZE, "%s: %s (%s)",
		    name, netshark_statustostr(status), fp->errbuf);
	else
		snprintf(errbuf, NETSHARK_ERRBUF_SIZE, "%s: %s",
		    name, netshark_statustostr(status));
	DIAG_ON_FORMAT_TRUNCATION
	netshark_close(fp);
	return (NULL);
}

struct netshark_samp *
netshark_setsampling(netshark_t *p)
{
#ifdef ENABLE_REMOTE
	return (&p->rmt_samp);
#else
	netsharkint_strlcpy(p->errbuf, "Capture sampling is not supported",
	    NETSHARK_ERRBUF_SIZE);
	return (NULL);
#endif
}
