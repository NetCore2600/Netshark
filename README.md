### NETSHARK 2600
```
███╗   ██╗███████╗████████╗███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗    ██████╗  ██████╗  ██████╗  ██████╗ 
████╗  ██║██╔════╝╚══██╔══╝██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝    ╚════██╗██╔════╝ ██╔═████╗██╔═████╗
██╔██╗ ██║█████╗     ██║   ███████╗███████║███████║██████╔╝█████╔╝      █████╔╝███████╗ ██║██╔██║██║██╔██║
██║╚██╗██║██╔══╝     ██║   ╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗     ██╔═══╝ ██╔═══██╗████╔╝██║████╔╝██║
██║ ╚████║███████╗   ██║   ███████║██║  ██║██║  ██║██║  ██║██║  ██╗    ███████╗╚██████╔╝╚██████╔╝╚██████╔╝
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝  ╚═════╝  ╚═════╝ 
```


### Installation

1. **Install Dependencies**
   - Install the PCAP development library:
     ```bash
     sudo apt-get install libpcap-dev  # For Debian/Ubuntu
     sudo yum install libpcap-devel    # For CentOS/RHEL
     ```

2. **Clone the Repository**
   ```bash
   git clone https://github.com/NetCore2600/Netshark.git
   cd netshark
   ```

3. **Build the Project**
   ```bash
   make
   ```

4. **Run the Program**
   ```bash
   ./netshark -i <interface> -f <filter>
   ```

Note: The program requires root privileges to capture network packets. Run it with `sudo` if needed.



### Architecture

Netshark is a network packet analyzer built with a modular and layered architecture. Here's how the components work together:

1. **Project Structure**
   ```
   netshark/
   ├── src/           # Source code
   │   ├── main.c     # Entry point and argument parsing
   │   ├── init.c     # Initialization routines
   │   └── handler.c  # Packet handling logic
   ├── include/       # Header files
   │   ├── netshark.h # Main application interface
   │   ├── handler.h  # Packet handler interface
   │   └── parser.h   # Argument parser interface
   ├── build/         # Compiled objects and binaries
   └── Makefile       # Build configuration
   ```

2. **Core Components**
   - **Main Application** (`main.c`)
     - Entry point of the program
     - Handles command-line arguments
     - Initializes the application
     - Manages the main event loop

   - **Packet Handler** (`handler.c`)
     - Processes captured network packets
     - Analyzes TCP/IP headers
     - Implements packet filtering
     - Formats and displays packet information

   - **Initialization** (`init.c`)
     - Sets up network interfaces
     - Configures packet capture
     - Manages resource allocation

3. **Data Flow**
   1. User inputs interface and filter parameters
   2. Main initializes the application
   3. Packet handler captures network traffic
   4. Packets are processed and analyzed
   5. Results are displayed in real-time

4. **Key Features**
   - Real-time packet capture
   - TCP/IP packet analysis
   - Flexible packet filtering
   - Detailed packet information display
   - Cross-platform compatibility

The architecture is designed to be modular, making it easy to maintain and extend. Each component has a clear responsibility, and the code is organized to separate concerns between packet capture, processing, and display.
