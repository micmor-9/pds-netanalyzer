use pcap::Device;

fn main() {

    for device in Device::list().expect("device lookup failed") {
        println!("Found device! {:?}", device);

    }
}