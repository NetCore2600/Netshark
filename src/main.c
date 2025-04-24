/* Netcore - Tshark

   Jonathan Tondelier
   Elie Marouani
   Jeremy Dufresne
   Loris Danel
   
   To compile:
   >gcc main.c -lpcap -o tshark

   Usage:
   ./tshark -i interface -f "filter"
   Example:
   ./tshark -i eth0 -f "tcp"
*/

#include "netcore.h"
#include "handler.h"

void print_usage(char *program_name) {
    printf("Usage: %s -i interface -f \"filter\"\n", program_name);
    printf("Example: %s -i eth0 -f \"tcp\"\n", program_name);
}

void parser_args(Args *args, int argc, char **argv) {
    args->dev = NULL;
    args->filter_exp = NULL;

    for (int i = 1; i < argc; i++) {
        
        if (strcmp(argv[i], "-i") == 0) {
            if (i + 1 < argc) {
                args->dev = argv[++i];
            } else {
                print_usage(argv[0]);
            }
        } else if (strcmp(argv[i], "-f") == 0) {
            if (i + 1 < argc) {
                args->filter_exp = argv[++i];
            } else {
                print_usage(argv[0]);
            }
        }

    }

    if (args->dev == NULL || args->filter_exp == NULL) {
        print_usage(argv[0]);
        exit(1);
    }
}


int main(int argc, char **argv) {
    Args args;
    NetCore app;

    parser_args(&args, argc, argv);

    init(&app, args);

    typedef void (*handler_fn)(const struct pcap_pkthdr *header, const unsigned char *packet);

    typedef struct {
        handler_fn tcp;
        handler_fn udp;
        handler_fn arp;
        handler_fn ftp;
        handler_fn http;
    } HandlerPacket;


    HandlerPacket handlers = {
        .tcp = tcp_handler,
        // .udp = handle_udp,
        // .arp = handle_arp,
        // .ftp = handle_ftp,
        // .http = handle_http
    };



    
    // get_handler(app);
    // -----------------------------------------------
    handler_fn selected_handler = NULL;

    if (strcmp(args.filter_exp, "tcp") == 0) {
        selected_handler = handlers.tcp;
    } else if (strcmp(args.filter_exp, "udp") == 0) {
        selected_handler = handlers.udp;
    } else if (strcmp(args.filter_exp, "arp") == 0) {
        selected_handler = handlers.udp;
    } else if (strcmp(args.filter_exp, "ftp") == 0) {
        selected_handler = handlers.udp;
    } else if (strcmp(args.filter_exp, "http") == 0) {
        selected_handler = handlers.udp;
    }
    // add more as needed...

    if (selected_handler == NULL) {
        fprintf(stderr, "Unsupported filter: %s\n", args.filter_exp);
        exit(1);
    }
    // -----------------------------------------------




    printf("\nStarting packet capture on %s with filter: %s\n", args.dev, args.filter_exp);
    while (1) {
        pcap_loop(app.handle, 10, selected_handler, NULL);
    }

    // Clean up
    pcap_freecode(&app.fp);
    pcap_close(app.handle);
    pcap_freealldevs(app.alldevs);

    return 0;
}
