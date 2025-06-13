// Import standard library modules
use std::io; // For I/O operations
use std::os::unix::io::RawFd; // Access I/O resources on Unix-like systems
use std::mem; // For working with memory manipulation

// Import libc functions and constants
use libc::{socket, recvfrom, sockaddr, AF_PACKET, SOCK_RAW, ETH_P_ALL}; // Import system functions and constants from the libc crate

// Function to create a raw socket 
// Returns a RawFd (file descriptor for the socket)
fn create_raw_socket() -> io::Result<RawFd> {
    // Unsafe block because calling `socket` is a low-level operation that directly interacts with the OS
    let fd = unsafe { 
        // Create a raw socket using the `socket` function from libc
        socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32) 
    };
    // Check if the socket creation failed (fd < 0 means failure in Unix systems)
    if fd < 0 {
        // Return the last OS error (from the system call) if socket creation failed
        Err(io::Error::last_os_error())
    } else {
        // Return fd if the socket creation succeeded
        Ok(fd)
    }
}

// Function to listen for and capture network packets from the socket (using the provided socket file descriptor)
fn sniff_packets(socket_fd: RawFd) -> io::Result<()> {
    // Create a buffer to hold the packet data (65536 bytes is a common buffer size for network packets)
    let mut buffer = [0u8; 65536];
    // Create a variable to hold the socket address structure, initialized to zero
    let mut addr: sockaddr = unsafe { mem::zeroed() };
    // Size of the address structure (needed for the `recvfrom` function)
    let mut addr_len = mem::size_of::<sockaddr>() as u32;

    // Start an infinite loop to continuously listen for packets
    loop {
        // Use unsafe block because `recvfrom` is a low-level system call
        let bytes_received = unsafe {
            // Call `recvfrom` to receive a packet from the socket
            recvfrom(
                socket_fd, // The socket file descriptor
                buffer.as_mut_ptr() as *mut _, // Pointer to the buffer where data will be stored
                buffer.len(), // Maximum number of bytes to read
                0, // Flags (0 means no special flags)
                &mut addr as *mut _, // Pointer to the address structure to store the sender's address
                &mut addr_len as *mut _, // Pointer to the address length
            )
        };

        // If the number of bytes received is less than 0, it means an error occurred
        if bytes_received < 0 {
            // Return the error from the system call
            return Err(io::Error::last_os_error());
        }

        // Print the captured packet's size (in bytes) and its raw data (hexadecimal format)
        println!("Captured {} bytes: {:x?}", bytes_received, &buffer[..bytes_received as usize]);
    }
}

// The main entry point for running the packet sniffer
pub fn run() -> io::Result<()> {
    // Create the raw socket by calling the `create_raw_socket` function
    let socket_fd = create_raw_socket()?;
    // Print a message indicating the raw socket is created and we are starting to listen
    println!("Raw socket created. Listening for packets...");
    // Start sniffing packets using the created socket
    sniff_packets(socket_fd)
}
