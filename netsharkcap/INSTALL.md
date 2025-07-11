# libnetshark installation notes

Platform-specific notes:
* [AIX](doc/README.aix)
* [Haiku](doc/README.haiku.md)
* [HP-UX](doc/README.hpux)
* [GNU/Hurd](doc/README.hurd.md)
* [GNU/Linux](doc/README.linux)
* [macOS](doc/README.macos)
* [Solaris and related OSes](doc/README.solaris.md)
* [Windows](doc/README.windows.md)

Hardware-specific notes:
* [Endace DAG](doc/README.dag.md)
* [Myricom SNF](doc/README.snf.md)

Libnetshark can be built either with the configure script and `make`, or
with CMake and any build system supported by CMake.

To build libnetshark with the configure script and `make`:

* If you build from a git clone rather than from a release archive,
run `./autogen.sh` (a shell script). The autogen.sh script will
build the `configure` and `config.h.in` files.

On some system, you may need to set the `AUTORECONF` variable, like:
`AUTORECONF=autoreconf-2.69 ./autogen.sh`
to select the `autoreconf` version you want to use.

* Run `./configure` (a shell script).  The configure script will
determine your system attributes and generate an appropriate `Makefile`
from `Makefile.in`.  The configure script has a number of options to
control the configuration of libnetshark; `./configure --help` will show
them.

* Next, run `make`.  If everything goes well, you can
`su` to root and run `make install`.  However, you need not install
libnetshark if you just want to build tcpdump; just make sure the tcpdump
and libnetshark directory trees have the same parent directory.

On OpenBSD, you may need to set, before the `make`, the `AUTOCONF_VERSION`
variable like:
`AUTOCONF_VERSION=2.69 make`

To build libnetshark with CMake and the build system of your choice, from
the command line:

* Create a build directory into which CMake will put the build files it
generates; CMake does not work as well with builds done in the source
code directory as does the configure script.  The build directory may be
created as a subdirectory of the source directory or as a directory
outside the source directory.

* Change to the build directory and run CMake with the path from the
build directory to the source directory as an argument.  The `-G` flag
can be used to select the CMake "generator" appropriate for the build
system you're using; various `-D` flags can be used to control the
configuration of libnetshark.

* Run the build tool.  If everything goes well, you can `su` to root and
run the build tool with the `install` target.  Building tcpdump from a
libnetshark in a build directory is not supported.

An `uninstall` target is supported with both `./configure` and CMake.

***DO NOT*** run the build as root; there is no need to do so, running
anything as root that doesn't need to be run as root increases the risk
of damaging your system, and running the build as root will put files in
the build directory that are owned by root and that probably cannot be
overwritten, removed, or replaced except by root, which could cause
permission errors in subsequent builds.

If configure says:

    configure: warning: cannot determine packet capture interface
    configure: warning: (see INSTALL.md file for more info)

or CMake says:

    cannot determine packet capture interface

    (see the INSTALL.md file for more info)

then your system either does not support packet capture or your system
does support packet capture but libnetshark does not support that
particular type.  If your system uses a
packet capture not supported by libnetshark, please send us patches; don't
forget to include an autoconf fragment suitable for use in
`configure.ac`.

It is possible to override the default packet capture type with the
`--with-netshark` option to `./configure` or the `-DNETSHARK_TYPE` option to
CMake, although the circumstances where this works are limited.  One
possible reason to do that would be to force a supported packet capture
type in the case where the configure or CMake scripts fails to detect
it.

You will need a C99 compiler to build libnetshark. The configure script
will abort if your compiler is not C99 compliant. If this happens, use
the generally available GNU C compiler (GCC) or Clang.

You will need either Flex 2.5.31 or later, or a version of Lex
compatible with it (if any exist), to build libnetshark.  The configure
script will abort if there isn't any such program; CMake fails if Flex
or Lex cannot be found, but doesn't ensure that it's compatible with
Flex 2.5.31 or later.  If you have an older version of Flex, or don't
have a compatible version of Lex, the current version of Flex is
available [here](https://github.com/westes/flex).

You will need either Bison, Berkeley YACC, or a version of YACC
compatible with them (if any exist), to build libnetshark.  The configure
script will abort if there isn't any such program; CMake fails if Bison
or some form of YACC cannot be found, but doesn't ensure that it's
compatible with Bison or Berkeley YACC.  If you don't have any such
program, the current version of Bison can be found
[here](https://ftp.gnu.org/gnu/bison/) and the current version of
Berkeley YACC can be found [here](https://invisible-island.net/byacc/).

Sometimes the stock C compiler does not interact well with Flex and
Bison. The list of problems includes undefined references for alloca(3).
You can get around this by installing GCC.

## Description of files
	CHANGES		    - description of differences between releases
	ChmodBPF/*	    - macOS startup item to set ownership and permissions on /dev/bpf*
	CMakeLists.txt	    - CMake file
	CONTRIBUTING.md	    - guidelines for contributing
	CREDITS		    - people that have helped libnetshark along
	INSTALL.md	    - this file
	LICENSE		    - the license under which libnetshark is distributed
	Makefile.in	    - compilation rules (input to the configure script)
	README.md	    - description of distribution
	doc/README.aix	    - notes on using libnetshark on AIX
	doc/README.dag.md   - notes on using libnetshark to capture on Endace DAG devices
	doc/README.haiku.md - notes on using libnetshark on Haiku
	doc/README.hpux	    - notes on using libnetshark on HP-UX
	doc/README.hurd.md  - notes on using libnetshark on GNU/Hurd
	doc/README.linux    - notes on using libnetshark on Linux
	doc/README.macos    - notes on using libnetshark on macOS
	doc/README.snf.md   - notes on using libnetshark to capture on Myricom SNF devices
	doc/README.solaris.md - notes on using libnetshark on Solaris
	doc/README.windows.md - notes on using libnetshark on Windows systems (with Nnetshark)
	VERSION		    - version of this release
	aclocal.m4	    - autoconf macros
	autogen.sh	    - build configure and config.h.in (run this first)
	bpf_dump.c	    - BPF program printing routines
	bpf_filter.c	    - BPF filtering routines
	bpf_image.c	    - BPF disassembly routine
	charconv.c	    - Windows Unicode routines
	charconv.h	    - Windows Unicode prototypes
	config.guess	    - autoconf support
	config.sub	    - autoconf support
	configure.ac	    - configure script source
	diag-control.h	    - compiler diagnostics control macros
	dlpisubs.c	    - DLPI-related functions for netshark-dlpi.c and netshark-libdlpi.c
	dlpisubs.h	    - DLPI-related function declarations
	etherent.c	    - /etc/ethers support routines
	extract.h	    - Alignment definitions
	ethertype.h	    - Ethernet protocol types and names definitions
	fad-getad.c	    - netshark_findalldevs() for systems with getifaddrs()
	fad-gifc.c	    - netshark_findalldevs() for systems with only SIOCGIFLIST
	fad-glifc.c	    - netshark_findalldevs() for systems with SIOCGLIFCONF
	fmtutils.c	    - error message formatting routines
	fmtutils.h	    - error message formatting prototypes
	ftmacros.h	    - feature test macros
	testprogs/TESTrun   - a script for "make check"
	testprogs/TESTlib.pm - TESTrun helper file
	testprogs/TESTmt.pm - TESTrun helper file
	testprogs/TESTst.pm - TESTrun helper file
	testprogs/filtertest.c      - test program for BPF compiler
	testprogs/findalldevstest.c - test program for netshark_findalldevs()
	gencode.c	    - BPF code generation routines
	gencode.h	    - BPF code generation definitions
	grammar.y	    - filter string grammar
	ieee80211.h	    - 802.11 definitions
	install-sh	    - BSD style install script
	instrument-functions.c - functions instrumentation calls for entry/exit
	lbl/os-*.h	    - OS-dependent defines and prototypes (if any)
	llc.h		    - 802.2 LLC SAP definitions
	missing/*	    - replacements for missing library functions
	mkdep		    - construct Makefile dependency list
	nametoaddr.c	    - hostname to address routines
	nametoaddr.h	    - hostname to address prototypes
	optimize.c	    - BPF optimization routines
	optimize.h	    - BPF optimization prototypes
	netshark/bluetooth.h    - public definition of DLT_BLUETOOTH_HCI_H4_WITH_PHDR header
	netshark/bpf.h	    - BPF definitions
	netshark/can_socketcan.h - SocketCAN header
	netshark/compiler-tests.h - compiler version comparison and other macros
	netshark/dlt.h	    - Link-layer header type codes.
	netshark/funcattrs.h    - function attribute macros
	netshark/ipnet.h	    - Solaris IPnet definitions
	netshark/namedb.h	    - public libnetshark name database definitions
	netshark/nflog.h	    - NFLOG-related definitions
	netshark/netshark.h	    - public libnetshark definitions
	netshark/netshark-inttypes.h - header for OS-specific integer type includes
	netshark/sll.h	    - public definitions of DLT_LINUX_SLL and DLT_LINUX_SLL2 headers
	netshark/socket.h	    - IP sockets support for various OSes
	netshark/usb.h	    - public definition of DLT_USB header
	netshark/vlan.h	    - VLAN-specific definitions
	netshark-bpf.c	    - BSD Packet Filter support
	netshark-bpf.h	    - header for backwards compatibility
	netshark-bt-linux.c	    - Bluetooth capture support for Linux
	netshark-bt-linux.h	    - Bluetooth capture support for Linux
	netshark-bt-monitor-linux.c - Bluetooth monitor capture support for Linux
	netshark-bt-monitor-linux.h - Bluetooth monitor capture support for Linux
	netshark-common.c	    - common code for netshark and netsharkng files
	netshark-common.h	    - common code for netshark and netsharkng files
	netshark-dag.c	    - Endace DAG device capture support
	netshark-dag.h	    - Endace DAG device capture support
	netshark-dbus.c	    - D-Bus capture support
	netshark-dbus.h	    - D-Bus capture support
	netshark-dlpi.c	    - Data Link Provider Interface support
	netshark-dpdk.c	    - DPDK device support
	netshark-dpdk.h	    - DPDK device support
	netshark-haiku.c	    - Haiku capture support
	netshark-hurd.c	    - GNU Hurd support
	netshark-int.h	    - internal libnetshark definitions
	netshark-libdlpi.c	    - Data Link Provider Interface support for systems with libdlpi
	netshark-linux.c	    - Linux packet socket support
	netshark-namedb.h	    - header for backwards compatibility
	netshark-netfilter-linux.c - Linux netfilter support
	netshark-netfilter-linux.h - Linux netfilter support
	netshark-netmap.c	    - netmap support
	netshark-netmap.h	    - netmap support
	netshark-npf.c	    - Nnetshark capture support
	netshark-null.c	    - dummy monitor support (allows offline use of libnetshark)
	netshark-rdmasniff.c    - RDMA/InfiniBand capture support
	netshark-rdmasniff.h    - RDMA/InfiniBand capture support
	netshark-rnetshark.c	    - RNETSHARK protocol capture support
	netshark-rnetshark.h	    - RNETSHARK protocol capture support
	netshark-snf.c	    - Myricom SNF device capture support
	netshark-snf.h	    - Myricom SNF device capture support
	netshark-types.h	    - header for OS-specific type includes
	netshark-usb-linux.c    - USB capture support for Linux
	netshark-usb-linux.h    - USB capture support for Linux
	netshark-usb-linux-common.c - Linux USB common routines
	netshark-usb-linux-common.h - Linux USB common prototypes
	netshark-util.c	    - common code for various files
	netshark-util.h	    - common code for various files
	netshark.3netshark	    - manual entry for the library
	netshark.c		    - netshark utility routines
	netshark.h		    - header for backwards compatibility
	netshark_*.3netshark	    - manual entries for library functions
	netshark-filter.manmisc.in   - manual entry for filter syntax
	netshark-linktype.manmisc.in - manual entry for link-layer header types
	pflog.h		    - header for DLT_PFLOG handling in filter code
	portability.h	    - Portability declarations/definitions
	ppp.h		    - Point to Point Protocol definitions
	rnetshark-protocol.c    - RNETSHARK client/server common routines
	rnetshark-protocol.h    - RNETSHARK client/server common prototypes
	savefile.c	    - offline support
	scanner.l	    - filter string scanner
	sf-netshark.c	    - routines for .netshark savefiles
	sf-netshark.h	    - prototypes for .netshark savefiles
	sf-netsharkng.c	    - routines for .netsharkng savefiles
	sf-netsharkng.h	    - prototypes for .netsharkng savefiles
	sockutils.c	    - socket and name lookup API routines
	sockutils.h	    - socket and name lookup API prototypes
	sslutils.c	    - OpenSSL interface routines
	sslutils.h	    - OpenSSL interface prototypes
	thread-local.h	    - header for some thread-safe support
	varattrs.h	    - variable attribute macros
