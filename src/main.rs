mod packet_sniffer;

fn main() {
    if let Err(e) = packet_sniffer::run() {
        eprintln!("Error: {}", e);
    }
}