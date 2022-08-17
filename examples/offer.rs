use std::mem::size_of;

use embedded_dhcp_client::DHCPMessage;
use embedded_dhcp_client::DHCPMessageRaw;
use embedded_dhcp_client::DecodeBuffer;
use embedded_dhcp_client::HType;
use embedded_dhcp_client::HwAddress;
use embedded_dhcp_client::Options;
use rand::{self, RngCore};
fn main() {
    // create socket
    let socket = std::net::UdpSocket::bind("0.0.0.0:68").unwrap();
    socket.set_broadcast(true).unwrap();
    // initialize rng.
    let mut rng = rand::thread_rng();
    // setup transaction id
    let xid = rng.next_u32();
    let mut mac_addr = [0; 6];
    // setup mac address.
    rng.fill_bytes(&mut mac_addr);
    println!("XID = {} , MAC Address = {:?}", xid, mac_addr);
    let hw_addr = HwAddress::Ethernet(&mac_addr);
    // fill parameter request list.
    let parameter_request_list = [1, 3, 6, 51, 58, 59];

    let discover_message =
        DHCPMessage::new_discover(xid, hw_addr, HType::Ethernet, &parameter_request_list);
    let discover_message: DHCPMessageRaw = discover_message.into();

    let message: [u8; std::mem::size_of::<DHCPMessageRaw>()] =
        unsafe { std::mem::transmute(discover_message) };
    socket
        .send_to(
            &message[0..(size_of::<DHCPMessageRaw>() - size_of::<usize>())],
            "255.255.255.255:67",
        )
        .unwrap();

    let mut recv_buffer = [0; 556];
    let (offer_message_size, addr) = socket.recv_from(&mut recv_buffer).unwrap();
    println!("received {} bytes from {}", offer_message_size, addr);
    let offer_message =
        unsafe { DHCPMessageRaw::decode_received_message(&recv_buffer, offer_message_size) };
    let offer_message = offer_message.decode_to_rustic_message(DecodeBuffer::Offer);
    println!("{:?}", offer_message);
    let xid = offer_message.xid;
    let offered_ip_addr = offer_message.yiaddr;
    if let Options::ServerIdentifer(server_ip_addr) = offer_message
        .options
        .iter()
        .find(|x| matches!(x, Options::ServerIdentifer(_)))
        .unwrap()
    {
        println!("offered ip address {:?}", offered_ip_addr);
        let request_message = DHCPMessage::new_request(
            xid,
            hw_addr,
            HType::Ethernet,
            offered_ip_addr,
            *server_ip_addr,
        );
        let request_message: DHCPMessageRaw = request_message.into();
        let message: [u8; std::mem::size_of::<DHCPMessageRaw>()] =
            unsafe { std::mem::transmute(request_message) };

        println!("built request message");
        socket
            .send_to(
                &message[0..(size_of::<DHCPMessageRaw>() - size_of::<usize>())],
                "255.255.255.255:67",
            )
            .unwrap();
        println!("send request message");
        let (ack_message_size, addr) = socket.recv_from(&mut recv_buffer).unwrap();
        println!("received {} bytes from {}", ack_message_size, addr);
        let ack_message =
            unsafe { DHCPMessageRaw::decode_received_message(&recv_buffer, ack_message_size) };
        let ack_message = ack_message.decode_to_rustic_message(DecodeBuffer::Ack);
        println!("{:?}", ack_message);
    }
}
