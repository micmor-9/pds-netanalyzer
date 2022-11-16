use pcap::{Device, Capture};

fn main() {
    let device = Device::lookup()
        .expect("device lookup failed")
        .expect("no device available");
    println!("Using device {}", device.name);

    let mut cap = Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    loop
    { println!("{:?}", cap.next_packet()); }
}