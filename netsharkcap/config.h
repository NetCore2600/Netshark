#ifndef CONFIG_H
#define CONFIG_H

// Configuration minimale pour netsharkcap
#define HAVE_SOCKADDR_SA_LEN 1
#define HAVE_STRUCT_SOCKADDR_SA_LEN 1

// Définitions pour Linux
#define HAVE_LINUX_NET_TSTAMP_H 1
#define HAVE_TPACKET3 1

// Autres définitions nécessaires
#define HAVE_OS_PROTO_H 1
#define HAVE_SYS_IOCCOM_H 1

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION "1.0.0"
#endif

#endif /* CONFIG_H */ 