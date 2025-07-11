/*
 * netshark-linux.c - Linux-specific code for Netshark
 * Allégé pour ne supporter que TCP/UDP/HTTP sur Linux
 */

#include "netshark-int.h"
#include "netshark-util.h"
#include "netshark/sll.h"
#include "netshark/vlan.h"

#include "diag-control.h"

/*
 * We require TPACKET_V2 support.
 */
#ifndef TPACKET2_HDRLEN
#error "Libnetshark will only work if TPACKET_V2 is supported; you must build for a 2.6.27 or later kernel"
#endif

/* check for memory mapped access availability. We assume every needed
 * struct is defined if the macro TPACKET_HDRLEN is defined, because it
 * uses many ring related structs and macros */
#ifdef TPACKET3_HDRLEN
# define HAVE_TPACKET3
#endif /* TPACKET3_HDRLEN */

/*
 * Not all compilers that are used to compile code to run on Linux have
 * these builtins.  For example, older versions of GCC don't, and at
 * least some people are doing cross-builds for MIPS with older versions
 * of GCC.
 */
#ifndef HAVE___ATOMIC_LOAD_N
#define __atomic_load_n(ptr, memory_model)		(*(ptr))
#endif
#ifndef HAVE___ATOMIC_STORE_N
#define __atomic_store_n(ptr, val, memory_model)	*(ptr) = (val)
#endif

#define packet_mmap_acquire(pkt) \
	(__atomic_load_n(&pkt->tp_status, __ATOMIC_ACQUIRE) != TP_STATUS_KERNEL)
#define packet_mmap_release(pkt) \
	(__atomic_store_n(&pkt->tp_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE))
#define packet_mmap_v3_acquire(pkt) \
	(__atomic_load_n(&pkt->hdr.bh1.block_status, __ATOMIC_ACQUIRE) != TP_STATUS_KERNEL)
#define packet_mmap_v3_release(pkt) \
	(__atomic_store_n(&pkt->hdr.bh1.block_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE))

#include <linux/types.h>
#include <linux/filter.h>

#ifdef HAVE_LINUX_NET_TSTAMP_H
#include <linux/net_tstamp.h>
#endif

#ifndef HAVE_SOCKLEN_T
typedef unsigned int	socklen_t;
#endif

#define MAX_LINKHEADER_SIZE	256

/*
 * When capturing on all interfaces we use this as the buffer size.
 * Should be bigger then all MTUs that occur in real life.
 * 64kB should be enough for now.
 */
#define BIGGER_THAN_ALL_MTUS	(64*1024)

/*
 * Private data for capturing on Linux PF_PACKET sockets.
 */
struct netshark_linux {
	long long sysfs_dropped; /* packets reported dropped by /sys/class/net/{if_name}/statistics/rx_{missed,fifo}_errors */
	struct netshark_stat stat;

	char	*device;	/* device name */
	int	filter_in_userland; /* must filter in userland */
	u_int	blocks_to_filter_in_userland;
	int	must_do_on_close; /* stuff we must do when we close */
	int	timeout;	/* timeout for buffering */
	int	cooked;		/* using SOCK_DGRAM rather than SOCK_RAW */
	int	ifindex;	/* interface index of device we're bound to */
	int	lo_ifindex;	/* interface index of the loopback device */
	int	netdown;	/* we got an ENETDOWN and haven't resolved it */
	bpf_u_int32 oldmode;	/* mode to restore when turning monitor mode off */
	char	*mondevice;	/* mac80211 monitor device we created */
	u_char	*mmapbuf;	/* memory-mapped region pointer */
	size_t	mmapbuflen;	/* size of region */
	int	vlan_offset;	/* offset at which to insert vlan tags; if -1, don't insert */
	u_int	tp_version;	/* version of tpacket_hdr for mmaped ring */
	u_int	tp_hdrlen;	/* hdrlen of tpacket_hdr for mmaped ring */
	u_char	*oneshot_buffer; /* buffer for copy of packet */
	int	poll_timeout;	/* timeout to use in poll() */
#ifdef HAVE_TPACKET3
	unsigned char *current_packet; /* Current packet within the TPACKET_V3 block. Move to next block if NULL. */
	int packets_left; /* Unhandled packets left within the block from previous call to netshark_read_linux_mmap_v3 in case of TPACKET_V3. */
#endif
	int poll_breakloop_fd; /* fd to an eventfd to break from blocking operations */
};

/*
 * Stuff to do when we close.
 */
#define MUST_DELETE_MONIF	0x00000001	/* delete monitor-mode interface */

/*
 * Prototypes for internal functions and methods.
 */
static int netshark_activate_linux(netshark_t *);
static int setup_socket(netshark_t *, int);
static int setup_mmapped(netshark_t *);
static int netshark_can_set_rfmon_linux(netshark_t *);
static int netshark_inject_linux(netshark_t *, const void *, int);
static int netshark_stats_linux(netshark_t *, struct netshark_stat *);
static int netshark_setfilter_linux(netshark_t *, struct bpf_program *);
static int netshark_setdirection_linux(netshark_t *, netshark_direction_t);
static int netshark_set_datalink_linux(netshark_t *, int);

union thdr {
	struct tpacket2_hdr		*h2;
#ifdef HAVE_TPACKET3
	struct tpacket_block_desc	*h3;
#endif
	u_char				*raw;
};

#define RING_GET_FRAME_AT(h, offset) (((u_char **)h->buffer)[(offset)])
#define RING_GET_CURRENT_FRAME(h) RING_GET_FRAME_AT(h, h->offset)

static void destroy_ring(netshark_t *handle);
static int create_ring(netshark_t *handle);
static int prepare_tpacket_socket(netshark_t *handle);
static int netshark_read_linux_mmap_v2(netshark_t *, int, netshark_handler , u_char *);
#ifdef HAVE_TPACKET3
static int netshark_read_linux_mmap_v3(netshark_t *, int, netshark_handler , u_char *);
#endif
static int netshark_setnonblock_linux(netshark_t *p, int nonblock);
static int netshark_getnonblock_linux(netshark_t *p);
static void netsharkint_oneshot_linux(u_char *user, const struct netshark_pkthdr *h,
    const u_char *bytes);

/*
 * In pre-3.0 kernels, the tp_vlan_tci field is set to whatever the
 * vlan_tci field in the skbuff is.  0 can either mean "not on a VLAN"
 * or "on VLAN 0".  There is no flag set in the tp_status field to
 * distinguish between them.
 *
 * In 3.0 and later kernels, if there's a VLAN tag present, the tp_vlan_tci
 * field is set to the VLAN tag, and the TP_STATUS_VLAN_VALID flag is set
 * in the tp_status field, otherwise the tp_vlan_tci field is set to 0 and
 * the TP_STATUS_VLAN_VALID flag isn't set in the tp_status field.
 *
 * With a pre-3.0 kernel, we cannot distinguish between packets with no
 * VLAN tag and packets on VLAN 0, so we will mishandle some packets, and
 * there's nothing we can do about that.
 *
 * So, on those systems, which never set the TP_STATUS_VLAN_VALID flag, we
 * continue the behavior of earlier libnetsharks, wherein we treated packets
 * with a VLAN tag of 0 as being packets without a VLAN tag rather than packets
 * on VLAN 0.  We do this by treating packets with a tp_vlan_tci of 0 and
 * with the TP_STATUS_VLAN_VALID flag not set in tp_status as not having
 * VLAN tags.  This does the right thing on 3.0 and later kernels, and
 * continues the old unfixably-imperfect behavior on pre-3.0 kernels.
 *
 * If TP_STATUS_VLAN_VALID isn't defined, we test it as the 0x10 bit; it
 * has that value in 3.0 and later kernels.
 */
#ifdef TP_STATUS_VLAN_VALID
  #define VLAN_VALID(hdr, hv)	((hv)->tp_vlan_tci != 0 || ((hdr)->tp_status & TP_STATUS_VLAN_VALID))
#else
  /*
   * This is being compiled on a system that lacks TP_STATUS_VLAN_VALID,
   * so we test with the value it has in the 3.0 and later kernels, so
   * we can test it if we're running on a system that has it.  (If we're
   * running on a system that doesn't have it, it won't be set in the
   * tp_status field, so the tests of it will always fail; that means
   * we behave the way we did before we introduced this macro.)
   */
  #define VLAN_VALID(hdr, hv)	((hv)->tp_vlan_tci != 0 || ((hdr)->tp_status & 0x10))
#endif

#ifdef TP_STATUS_VLAN_TPID_VALID
# define VLAN_TPID(hdr, hv)	(((hv)->tp_vlan_tpid || ((hdr)->tp_status & TP_STATUS_VLAN_TPID_VALID)) ? (hv)->tp_vlan_tpid : ETH_P_8021Q)
#else
# define VLAN_TPID(hdr, hv)	((hv)->tp_vlan_tpid ? (hv)->tp_vlan_tpid : ETH_P_8021Q)
#endif

static const struct timeval netdown_timeout = {
	.tv_sec = 1,
	.tv_usec = 0
};

static int	iface_get_id(int fd, const char *device, char *ebuf);
static int	iface_get_mtu(int fd, const char *device, char *ebuf);
static int	iface_get_arptype(int fd, const char *device, char *ebuf);
static int	iface_bind(int fd, int ifindex, char *ebuf, int protocol);

/*
 * Linux-specific implementation of netshark_activate for PF_PACKET sockets.
 */
static int
netshark_activate_linux(netshark_t *handle)
{
	struct netshark_linux *handlep = handle->priv;
	int status = 0;
	int is_any_device = 0;
	struct ifreq	ifr;

	/*
	 * Turn a negative snapshot value (invalid) into the largest
	 * possible value.
	 */
	if (handle->snapshot < 0)
		handle->snapshot = 65535;

	if (handle->opt.rfmon) {
		/*
		 * Monitor mode doesn't apply to devices that don't
		 * support it.
		 */
		if (!netshark_can_set_rfmon_linux(handle)) {
			snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
			    "Monitor mode not supported on device %s",
			    handle->opt.device);
			return (NETSHARK_ERROR_RFMON_NOTSUP);
		}
	}

	/*
	 * "any" is a special device that captures on all interfaces.
	 */
	if (strcmp(handle->opt.device, "any") == 0) {
		is_any_device = 1;
		handle->linktype = DLT_LINUX_SLL;
		handle->dlt_list = NULL;
		handle->dlt_count = 0;
	} else {
		/*
		 * Get the interface index and type.
		 */
		if (iface_get_id(handle->fd, handle->opt.device,
		    handle->errbuf) == -1) {
			/*
			 * If we can't get the interface ID, this might
			 * be a "any" device name (which isn't actually
			 * a real interface), so try opening it as if
			 * it were an "any" device.
			 */
			if (strcmp(handle->opt.device, "any") == 0) {
				is_any_device = 1;
				handle->linktype = DLT_LINUX_SLL;
				handle->dlt_list = NULL;
				handle->dlt_count = 0;
			} else {
				return (NETSHARK_ERROR);
			}
		} else {
			/*
			 * Get the interface type.
			 */
			if (iface_get_arptype(handle->fd, handle->opt.device,
			    handle->errbuf) == -1) {
				return (NETSHARK_ERROR);
			}
		}
	}

	/*
	 * Set up the socket.
	 */
	if (setup_socket(handle, is_any_device) == -1) {
		return (NETSHARK_ERROR);
	}

	/*
	 * Set the buffer size.
	 */
	if (handle->opt.buffer_size != 0) {
		if (setsockopt(handle->fd, SOL_SOCKET, SO_RCVBUF,
		    &handle->opt.buffer_size, sizeof(handle->opt.buffer_size)) == -1) {
			snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
			    "SO_RCVBUF: %s", strerror(errno));
			return (NETSHARK_ERROR);
		}
	}

	/*
	 * Set the timeout.
	 */
	if (handle->opt.timeout != 0) {
		struct timeval to;

		to.tv_sec = handle->opt.timeout / 1000;
		to.tv_usec = (handle->opt.timeout % 1000) * 1000;
		if (setsockopt(handle->fd, SOL_SOCKET, SO_RCVTIMEO,
		    &to, sizeof(to)) == -1) {
			snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
			    "SO_RCVTIMEO: %s", strerror(errno));
			return (NETSHARK_ERROR);
		}
	}

	/*
	 * Set the snapshot length.
	 */
	if (setsockopt(handle->fd, SOL_PACKET, PACKET_RX_RING,
	    &handle->snapshot, sizeof(handle->snapshot)) == -1) {
		snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
		    "PACKET_RX_RING: %s", strerror(errno));
		return (NETSHARK_ERROR);
	}

	/*
	 * Set up memory-mapped access if requested.
	 */
	if (handle->opt.immediate) {
		if (setup_mmapped(handle) == -1) {
			return (NETSHARK_ERROR);
		}
	}

	/*
	 * Set the direction.
	 */
	if (handle->opt.direction != NETSHARK_D_INOUT) {
		if (netshark_setdirection_linux(handle, handle->opt.direction) == -1) {
			return (NETSHARK_ERROR);
		}
	}

	/*
	 * Set the datalink type.
	 */
	if (handle->opt.datalink != -1) {
		if (netshark_set_datalink_linux(handle, handle->opt.datalink) == -1) {
			return (NETSHARK_ERROR);
		}
	}

	/*
	 * Set the filter.
	 */
	if (handle->opt.rfmon) {
		/*
		 * Monitor mode doesn't apply to devices that don't
		 * support it.
		 */
		if (!netshark_can_set_rfmon_linux(handle)) {
			snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
			    "Monitor mode not supported on device %s",
			    handle->opt.device);
			return (NETSHARK_ERROR_RFMON_NOTSUP);
		}
	}

	return (0);
}

/*
 * Linux-specific implementation of netshark_can_set_rfmon for PF_PACKET sockets.
 */
static int
netshark_can_set_rfmon_linux(netshark_t *handle)
{
	/*
	 * For now, we don't support monitor mode on Linux.
	 * This could be implemented in the future.
	 */
	return (0);
}

/*
 * Linux-specific implementation of netshark_inject for PF_PACKET sockets.
 */
static int
netshark_inject_linux(netshark_t *handle, const void *buf, int size)
{
	struct netshark_linux *handlep = handle->priv;
	int ret;

	/*
	 * Send the packet.
	 */
	ret = send(handle->fd, buf, size, 0);
	if (ret == -1) {
		snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
		    "send: %s", strerror(errno));
		return (-1);
	}

	return (ret);
}

/*
 * Linux-specific implementation of netshark_stats for PF_PACKET sockets.
 */
static int
netshark_stats_linux(netshark_t *handle, struct netshark_stat *stats)
{
	struct netshark_linux *handlep = handle->priv;
	struct tpacket_stats_v3 kstats;
	socklen_t len = sizeof(struct tpacket_stats_v3);

	/*
	 * Get the statistics.
	 */
	if (getsockopt(handle->fd, SOL_PACKET, PACKET_STATISTICS,
	    &kstats, &len) == -1) {
		snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
		    "PACKET_STATISTICS: %s", strerror(errno));
		return (-1);
	}

	stats->ps_recv = kstats.tp_packets;
	stats->ps_drop = kstats.tp_drops;
	stats->ps_ifdrop = 0;

	return (0);
}

/*
 * Linux-specific implementation of netshark_setfilter for PF_PACKET sockets.
 */
static int
netshark_setfilter_linux(netshark_t *handle, struct bpf_program *filter)
{
	struct netshark_linux *handlep = handle->priv;
	struct sock_fprog fcode;

	/*
	 * Set the filter.
	 */
	fcode.len = filter->bf_len;
	fcode.filter = (struct sock_filter *)filter->bf_insns;
	if (setsockopt(handle->fd, SOL_SOCKET, SO_ATTACH_FILTER,
	    &fcode, sizeof(fcode)) == -1) {
		snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
		    "SO_ATTACH_FILTER: %s", strerror(errno));
		return (-1);
	}

	return (0);
}

/*
 * Linux-specific implementation of netshark_setdirection for PF_PACKET sockets.
 */
static int
netshark_setdirection_linux(netshark_t *handle, netshark_direction_t d)
{
	int direction;

	switch (d) {

	case NETSHARK_D_INOUT:
		direction = PACKET_BOTH;
		break;

	case NETSHARK_D_IN:
		direction = PACKET_IN;
		break;

	case NETSHARK_D_OUT:
		direction = PACKET_OUT;
		break;

	default:
		snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
		    "Invalid direction %d", d);
		return (-1);
	}

	if (setsockopt(handle->fd, SOL_PACKET, PACKET_RECV_OUTPUT,
	    &direction, sizeof(direction)) == -1) {
		snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
		    "PACKET_RECV_OUTPUT: %s", strerror(errno));
		return (-1);
	}

	return (0);
}

/*
 * Linux-specific implementation of netshark_set_datalink for PF_PACKET sockets.
 */
static int
netshark_set_datalink_linux(netshark_t *handle, int dlt)
{
	/*
	 * For now, we only support Ethernet and Linux SLL.
	 */
	switch (dlt) {

	case DLT_EN10MB:
	case DLT_LINUX_SLL:
		handle->linktype = dlt;
		break;

	default:
		snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
		    "Unsupported datalink type %d", dlt);
		return (-1);
	}

	return (0);
}

/*
 * Set up the socket for capturing.
 */
static int
setup_socket(netshark_t *handle, int is_any_device)
{
	struct netshark_linux *handlep = handle->priv;
	struct sockaddr_ll sll;
	int protocol;

	/*
	 * Determine the protocol to use.
	 */
	if (is_any_device) {
		protocol = ETH_P_ALL;
	} else {
		protocol = ETH_P_ALL;
	}

	/*
	 * Bind the socket to the interface.
	 */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(protocol);
	sll.sll_ifindex = handlep->ifindex;

	if (bind(handle->fd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
		snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
		    "bind: %s", strerror(errno));
		return (-1);
	}

	return (0);
}

/*
 * Set up memory-mapped access.
 */
static int
setup_mmapped(netshark_t *handle)
{
	struct netshark_linux *handlep = handle->priv;
	struct tpacket_req req;

	/*
	 * Set up the ring buffer.
	 */
	memset(&req, 0, sizeof(req));
	req.tp_block_size = 4096;
	req.tp_block_nr = 256;
	req.tp_frame_size = 2048;
	req.tp_frame_nr = 512;

	if (setsockopt(handle->fd, SOL_PACKET, PACKET_RX_RING,
	    &req, sizeof(req)) == -1) {
		snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
		    "PACKET_RX_RING: %s", strerror(errno));
		return (-1);
	}

	/*
	 * Map the ring buffer.
	 */
	handlep->mmapbuf = mmap(NULL, req.tp_block_size * req.tp_block_nr,
	    PROT_READ | PROT_WRITE, MAP_SHARED, handle->fd, 0);
	if (handlep->mmapbuf == MAP_FAILED) {
		snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
		    "mmap: %s", strerror(errno));
		return (-1);
	}

	handlep->mmapbuflen = req.tp_block_size * req.tp_block_nr;
	handlep->tp_version = TPACKET_V2;
	handlep->tp_hdrlen = sizeof(struct tpacket2_hdr);

	return (0);
}

/*
 * Get the interface ID.
 */
static int
iface_get_id(int fd, const char *device, char *ebuf)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name) - 1);

	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		snprintf(ebuf, NETSHARK_ERRBUF_SIZE,
		    "SIOCGIFINDEX: %s", strerror(errno));
		return (-1);
	}

	return (ifr.ifr_ifindex);
}

/*
 * Get the interface MTU.
 */
static int
iface_get_mtu(int fd, const char *device, char *ebuf)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name) - 1);

	if (ioctl(fd, SIOCGIFMTU, &ifr) == -1) {
		snprintf(ebuf, NETSHARK_ERRBUF_SIZE,
		    "SIOCGIFMTU: %s", strerror(errno));
		return (-1);
	}

	return (ifr.ifr_mtu);
}

/*
 * Get the interface ARP type.
 */
static int
iface_get_arptype(int fd, const char *device, char *ebuf)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name) - 1);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
		snprintf(ebuf, NETSHARK_ERRBUF_SIZE,
		    "SIOCGIFHWADDR: %s", strerror(errno));
		return (-1);
	}

	return (ifr.ifr_hwaddr.sa_family);
}

/*
 * Bind the socket to an interface.
 */
static int
iface_bind(int fd, int ifindex, char *ebuf, int protocol)
{
	struct sockaddr_ll sll;
	socklen_t addr_len = sizeof(sll);

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(protocol);
	sll.sll_ifindex = ifindex;

	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
		snprintf(ebuf, NETSHARK_ERRBUF_SIZE,
		    "bind: %s", strerror(errno));
		return (-1);
	}

	return (0);
}

/*
 * Linux-specific implementation of netshark_read for PF_PACKET sockets.
 */
static int
netshark_read_linux(netshark_t *handle, int max_packets, netshark_handler callback,
    u_char *user)
{
	struct netshark_linux *handlep = handle->priv;
	int packets_read = 0;
	int ret;

	/*
	 * If we're using memory-mapped access, use the memory-mapped
	 * read routine.
	 */
	if (handlep->mmapbuf != NULL) {
		if (handlep->tp_version == TPACKET_V2) {
			ret = netshark_read_linux_mmap_v2(handle, max_packets,
			    callback, user);
		} else {
			ret = netshark_read_linux_mmap_v3(handle, max_packets,
			    callback, user);
		}
		return (ret);
	}

	/*
	 * Otherwise, use the regular read routine.
	 */
	while (max_packets == 0 || packets_read < max_packets) {
		u_char *bp;
		struct netshark_pkthdr pkthdr;
		int status;

		/*
		 * Read the packet.
		 */
		status = recv(handle->fd, handle->buffer, handle->snapshot, 0);
		if (status == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				/*
				 * No packets available.
				 */
				break;
			}
			snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
			    "recv: %s", strerror(errno));
			return (-1);
		}

		/*
		 * Set up the packet header.
		 */
		pkthdr.len = status;
		pkthdr.caplen = status;
		gettimeofday(&pkthdr.ts, NULL);

		/*
		 * Call the callback.
		 */
		bp = handle->buffer;
		(*callback)(user, &pkthdr, bp);

		packets_read++;
	}

	return (packets_read);
}

/*
 * Linux-specific implementation of netshark_read for memory-mapped PF_PACKET sockets.
 */
static int
netshark_read_linux_mmap_v2(netshark_t *handle, int max_packets, netshark_handler callback,
    u_char *user)
{
	struct netshark_linux *handlep = handle->priv;
	union thdr h;
	unsigned int frame_offset = 0;
	int packets_read = 0;

	/*
	 * Get the current frame.
	 */
	h.raw = handlep->mmapbuf + frame_offset;

	/*
	 * Process frames until we've read enough packets or there are no more.
	 */
	while (max_packets == 0 || packets_read < max_packets) {
		/*
		 * Check if we have a packet.
		 */
		if (h.h2->tp_status & TP_STATUS_USER) {
			/*
			 * We have a packet.
			 */
			struct netshark_pkthdr pkthdr;
			u_char *bp;

			/*
			 * Set up the packet header.
			 */
			pkthdr.len = h.h2->tp_len;
			pkthdr.caplen = h.h2->tp_snaplen;
			pkthdr.ts.tv_sec = h.h2->tp_sec;
			pkthdr.ts.tv_usec = h.h2->tp_usec;

			/*
			 * Get the packet data.
			 */
			bp = (u_char *)h.h2 + h.h2->tp_mac;

			/*
			 * Call the callback.
			 */
			(*callback)(user, &pkthdr, bp);

			packets_read++;

			/*
			 * Mark the packet as available for the kernel.
			 */
			h.h2->tp_status = TP_STATUS_KERNEL;
		}

		/*
		 * Move to the next frame.
		 */
		frame_offset += handlep->tp_hdrlen;
		if (frame_offset >= handlep->mmapbuflen) {
			frame_offset = 0;
		}
		h.raw = handlep->mmapbuf + frame_offset;
	}

	return (packets_read);
}

#ifdef HAVE_TPACKET3
/*
 * Linux-specific implementation of netshark_read for memory-mapped PF_PACKET sockets with TPACKET_V3.
 */
static int
netshark_read_linux_mmap_v3(netshark_t *handle, int max_packets, netshark_handler callback,
    u_char *user)
{
	/*
	 * TPACKET_V3 is not implemented in this simplified version.
	 */
	return (0);
}
#endif

/*
 * Linux-specific implementation of netshark_setnonblock for PF_PACKET sockets.
 */
static int
netshark_setnonblock_linux(netshark_t *handle, int nonblock)
{
	int flags;

	flags = fcntl(handle->fd, F_GETFL, 0);
	if (flags == -1) {
		snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
		    "fcntl: %s", strerror(errno));
		return (-1);
	}

	if (nonblock) {
		flags |= O_NONBLOCK;
	} else {
		flags &= ~O_NONBLOCK;
	}

	if (fcntl(handle->fd, F_SETFL, flags) == -1) {
		snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
		    "fcntl: %s", strerror(errno));
		return (-1);
	}

	return (0);
}

/*
 * Linux-specific implementation of netshark_getnonblock for PF_PACKET sockets.
 */
static int
netshark_getnonblock_linux(netshark_t *handle)
{
	int flags;

	flags = fcntl(handle->fd, F_GETFL, 0);
	if (flags == -1) {
		snprintf(handle->errbuf, NETSHARK_ERRBUF_SIZE,
		    "fcntl: %s", strerror(errno));
		return (-1);
	}

	return ((flags & O_NONBLOCK) != 0);
}

/*
 * Linux-specific implementation of netshark_oneshot for PF_PACKET sockets.
 */
static void
netsharkint_oneshot_linux(u_char *user, const struct netshark_pkthdr *h,
    const u_char *bytes)
{
	struct oneshot_userdata *sp = (struct oneshot_userdata *)user;
	netshark_t *handle = sp->handle;
	struct netshark_linux *handlep = handle->priv;

	/*
	 * Copy the packet to the oneshot buffer.
	 */
	if (h->caplen > handle->snapshot) {
		handlep->oneshot_buffer = realloc(handlep->oneshot_buffer,
		    h->caplen);
	}
	memcpy(handlep->oneshot_buffer, bytes, h->caplen);

	/*
	 * Set the packet header.
	 */
	sp->hdr = *h;
	sp->hdr.caplen = h->caplen;
	sp->hdr.len = h->len;
	sp->hdr.ts = h->ts;

	/*
	 * Set the packet data.
	 */
	sp->pkt = handlep->oneshot_buffer;
}

/*
 * Linux-specific implementation of netshark_cleanup for PF_PACKET sockets.
 */
static void
netshark_cleanup_linux(netshark_t *handle)
{
	struct netshark_linux *handlep = handle->priv;

	/*
	 * Unmap the memory-mapped buffer if it was mapped.
	 */
	if (handlep->mmapbuf != NULL) {
		munmap(handlep->mmapbuf, handlep->mmapbuflen);
		handlep->mmapbuf = NULL;
		handlep->mmapbuflen = 0;
	}

	/*
	 * Free the oneshot buffer if it was allocated.
	 */
	if (handlep->oneshot_buffer != NULL) {
		free(handlep->oneshot_buffer);
		handlep->oneshot_buffer = NULL;
	}
}

/*
 * Linux-specific implementation of netshark_breakloop for PF_PACKET sockets.
 */
static void
netshark_breakloop_linux(netshark_t *handle)
{
	struct netshark_linux *handlep = handle->priv;
	uint64_t value = 1;

	/*
	 * Write to the breakloop file descriptor to wake up any
	 * blocking operations.
	 */
	if (handlep->poll_breakloop_fd != -1) {
		(void)write(handlep->poll_breakloop_fd, &value, sizeof(value));
	}
}

/*
 * Linux-specific implementation of netshark_platform_finddevs.
 */
int
netsharkint_platform_finddevs(netshark_if_list_t *devlistp, char *errbuf)
{
	/*
	 * For now, we don't implement device enumeration.
	 * This could be implemented in the future.
	 */
	return (0);
}

/*
 * Linux-specific implementation of netshark_set_protocol.
 */
int
netshark_set_protocol_linux(netshark_t *p, int protocol)
{
	/*
	 * For now, we don't implement protocol setting.
	 * This could be implemented in the future.
	 */
	return (0);
}
