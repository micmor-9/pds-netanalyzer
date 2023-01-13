![](logo.png "prj_name")

## Project Overview

**net-analyzer**, also known as a packet sniffer or protocol analyzer, is a tool or software that is used to capture, analyze, and inspect network traffic. It can be used to monitor network activity, troubleshoot network issues, and detect security threats. Network analyzers capture packets of data that are transmitted over a network and allow the user to view the packets in a detailed format, such as the source and destination IP addresses, ports, and protocol information. They can also be used to filter and search for specific types of packets, and to generate reports on network activity.

## Installation

Rust is a programming language that can be installed on various system, including Windows, macOS, and Linux.
To install Rust on your system, you will need to install the `rustc` (Rust compiler) ,`cargo` (Rust package manager) tools.

Here are the general steps to install Rust on your system:

1. Download and install the Rustup installer from the official Rust website: https://www.rust-lang.org/tools/install
2. Run the Rustup installer, which will download and install the latest version of Rust.

3. Open a terminal or command prompt and run the following command to confirm that Rust and cargo has been installed has been installed correctly:\
      `rustc --version`\
      `cargo --version`\
   On Windows, the installation process is similar, and you can use the rustup-init.exe installer to install Rust. On Linux and macOS, you can also use package manager, like apt-get or brew, to install Rust.

## Usage

> **NOTE**
> The application needs to be run with admin priviledges in order to correctly use the specified interface to sniff traffic.
> You have to install(on Windows, on mac is already installed) and use `pcap` (a lib dedicated to the sniffing).

The application can be run in several way and with several arguments thanks to the `clap` lib\
  `cargo run -- -c, -commands`   Shows all possible commands\
  `cargo run -- -l, -list`   Shows a list with all available interfaces\
  `cargo run -- -f, -filters` Let the user specify some filters to apply to the sniffing:\
Filter is a struct with the following fields:\

1. Source Ip(String)\
2. Destination Ip(String)\
3. Source Port(String)\
4. Destination Port(String)\
5. Transport Protocol(String)\

The app will check if filters inserted are valid or not\
The application will follow settings specified in the setting.conf file\
If it is runned with the command `cargo run` the app will ask the user to create the default configuration file that will have fixed parameters:\

1. Default Interface available\
2. Report writed in txt mode\
3. Timeout to create reports in seconds (10)\
4. Exit FileName "report"\
5. No filters\

This configuration will be read and will create a JSON object that will generate the Setting Struct, with the 5 fields:\

1. Interface(Option<String>)\
2. Csv(Option<Bool>)\
3. Timeout(Option<i64>)\
4. Filename(Option<String>)\
5. Filter(Option<Filter>)\

To change the configuration file and the settings parameters, user can add some flags to the `cargo run` command:\
  `cargo run -- -i, -interface <Interface_Name>` Set a specific interface\
  `cargo run -- -o, -output_type <Output_Type>` Set output type(Txt or Csv)\
  `cargo run -- -r, -reportname <Report_Name>` Set report name\

In the end the user can reset all the filters thanks to the command   `cargo run -- -w, -wreset_filters`\

After running the application with a configuration file it is possible to start the sniffing by pressing Enter and pause the sniffing pressing Enter again\
To stop the application after pausing it, it is necessary to press q and then press Enter\
After every timeout , the application will create the report of Sniffed packets (Csv or TxT) with all the information:\
"Interface"\
"Source IP"\
"Destination IP"\
"Source Port"\
"Destination Port"\
"Bytes"\
"Transport Protocol"\
"Application Protocol"\
"Timestamp"\

And a message will be sent to the shell "Report # {} generated at {}", with the report number and timestamp\

The report is generated thanks to the report module\
It sets the permissions to create and write on a file, and the struct ReportWriter will be used to write the report:\
The struct contains the following attributes:\

1. csv_or_txt(Bool)\
2. filename: (String)\
3. num: (i32)\
4. csv_writer: (Option<Box<Writer<File>>>)\
5. txt_writer: (Option<Box<File>>)\

It will set, according to the settings, the field csv_or_txt and then create a csv writer or a txt writer. The filename will be taken from the settings too and the num is just a counter\
to write with the report filename to differ every report generated in that session, plus its date.\

In the main module, threads are handled.\
First of all pcap capture is set to promisc mode to the selected interface and a result is returned to check if there's an error.\
There are channels to let threads communicate with each other, in particular the sniffer thread communicates with the parser thread and the parser thread communicates with the report\ thread.\
There is a boolean state managed with RwLock that handles the pause/resume events during the sniffing process and is shared among all the threads.\
The thread responsible for the effective sniffing via network will start, receive the packet in a Vec<u8> format, send all the bits to the parser, that will try to process these information and send them to the report thread.\
This one after the timeout time, thanks to a boolean flag handled by a scheduled task, will create and write the report.\

The error module gives information about all the errors to handle. The errors with a short description are displayed to the user during the sniffing process.

1. EthernetPacketUnrecognized => "Ethernet Packet not recognized!"
2. EthernetPacketError => "Ethernet Packet error!"
3. ArpPacketError => "ARP Packet error!"
4. IPv4PacketError => "IPv4 Packet error!"
5. IPv6PacketError => "IPv6 Packet error!"
6. TransportProtocolError => "Transport Protocol error!"
7. TCPSegmentError => "TCP Segment error!"
8. UDPDatagramError => "UDP Datagram error!"
9. ICMPPacketError => "ICMP Packet error!"
10. GenericError => "Generic error!"

## Credits:
Di Ciaula Roberto <r.diciaula@studenti.polito.it>\
Galati Michele <m.galati@studenti.polito.it>\
Morgigno Michele <m.morgigno@studenti.polito.it>