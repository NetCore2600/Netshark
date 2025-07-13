/* Netcore 2600 - NetShark

   Jonathan Tondelier
   Elie Marouani
   Jeremy Dufresne
   Loris Danel
*/

#include "netshark.h"

int DEBUG_MODE = 0;

void parse_env()
{
    char *debug = getenv("DEBUG");
    if (debug)
    {
        DEBUG_MODE = 1;
    }
}

void print_usage(char *program_name)
{
    printf("Usage: %s -i interface -f \"filter\"\n", program_name);
    printf("Example: %s -i eth0 -f \"tcp\"\n", program_name);
}

void parser_args(Args *args, int argc, char **argv)
{
    args->dev = NULL;
    args->filter_exp = NULL;

    for (int i = 1; i < argc; i++)
    {

        if (strcmp(argv[i], "-i") == 0)
        {
            if (i + 1 < argc)
            {
                args->dev = argv[++i];
            }
            else
            {
                print_usage(argv[0]);
            }
        }
        else if (strcmp(argv[i], "-f") == 0)
        {
            if (i + 1 < argc)
            {
                args->filter_exp = argv[++i];
            }
            else
            {
                print_usage(argv[0]);
            }
        }
    }

    if (args->dev == NULL || args->filter_exp == NULL)
    {
        print_usage(argv[0]);
        exit(1);
    }
}

int main(int argc, char **argv)
{
    Args args;
    NetShark app;

    parse_env();
    parser_args(&args, argc, argv);

    init(&app, args);

    printf("\nStarting packet capture on %s with filter: %s\n", args.dev, args.filter_exp);
    while (1)
    {
        pcap_loop(app.handle, 1, app.handler, NULL);
    }

    // Clean up
    pcap_freecode(&app.fp);
    pcap_close(app.handle);
    pcap_freealldevs(app.alldevs);

    return 0;
}
