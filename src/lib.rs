//! # Rust Data Transfer Protocol
//!
//! Asynchronous cross-platform networking interfaces for Rust.
//!
//! The two fundamental network objects this crate provides are the server and client. When starting a server or connecting via a client, the task will not block while it performs network operations in the background. Upon instantiation, both the server and client return handles that provide a mechanism for communicating with the background task, and instructing it to provide status information or halt network operations.
//!
//! ## Creating a server
//!
//! A server can be built using the `Server` implementation:
//!
//! ```no_run
//! use rustdtp::{Server, ServerEvent, EventStreamExt};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create a server that receives strings and returns the length of each string
//!     let (mut server, mut server_event) = Server::<usize, String>::start(("0.0.0.0", 0)).await.unwrap();
//!
//!     // Iterate over events
//!     while let Some(event) = server_event.next().await {
//!         match event {
//!             ServerEvent::Connect { client_id } => {
//!                 println!("Client with ID {} connected", client_id);
//!             }
//!             ServerEvent::Disconnect { client_id } => {
//!                 println!("Client with ID {} disconnected", client_id);
//!             }
//!             ServerEvent::Receive { client_id, data } => {
//!                 // Send back the length of the string
//!                 server.send(client_id, data.len()).await.unwrap();
//!             }
//!             ServerEvent::Stop => {
//!                 // No more events will be sent, and the loop will end
//!                 println!("Server closed");
//!             }
//!         }
//!     }
//! }
//! ```
//!
//! ## Creating a client
//!
//! A client can be built using the `Client` implementation:
//!
//! ```no_run
//! use rustdtp::{Client, ClientEvent, EventStreamExt};
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create a client that sends a message to the server and receives the length of the message
//!     let (mut client, mut client_event) = Client::<String, usize>::connect(("127.0.0.1", 29275)).await.unwrap();
//!
//!     // Send a message to the server
//!     let msg = "Hello, server!".to_owned();
//!     client.send(msg.clone()).await.unwrap();
//!
//!     // Receive the response
//!     match client_event.next().await.unwrap() {
//!         ClientEvent::Receive { data } => {
//!             // Validate the response
//!             println!("Received response from server: {}", data);
//!             assert_eq!(data, msg.len());
//!         }
//!         event => {
//!             // Unexpected response
//!             panic!("expected to receive a response from the server, instead got {:?}", event);
//!         }
//!     }
//! }
//! ```
//!
//! ## Event iteration
//!
//! Note that in order to iterate over events, the `EventStreamExt` extension trait needs to be in scope.
//!
//! ## Security
//!
//! Information security comes included. Every message sent over a network interface is encrypted with AES-256. Key exchanges are performed using a 2048-bit RSA key-pair.

#![crate_type = "lib"]
#![crate_name = "rustdtp"]

/// Types re-exported from the crate.
pub use tokio_stream::StreamExt as EventStreamExt;

/// Types exported from the crate.
pub use client::{Client, ClientEvent, ClientHandle};
pub use event_stream::EventStream;
pub use server::{Server, ServerEvent, ServerHandle};

mod client;
mod command_channel;
mod crypto;
mod event_stream;
mod server;
mod util;

/// Crate tests.
#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use rand;

    use util::*;

    use super::*;

    /// Default amount of time to sleep, in milliseconds.
    const SLEEP_TIME: u64 = 100;
    /// Default server address.
    const SERVER_ADDR: (&'static str, u16) = ("127.0.0.1", 0);

    /// Sleep for a desired duration.
    macro_rules! sleep {
        ($x:expr) => {
            thread::sleep(Duration::from_millis($x))
        };
        () => {
            thread::sleep(Duration::from_millis(SLEEP_TIME))
        };
    }

    /// Test the message size portion encoding.
    #[test]
    fn test_encode_message_size() {
        assert_eq!(encode_message_size(0), [0, 0, 0, 0, 0]);
        assert_eq!(encode_message_size(1), [0, 0, 0, 0, 1]);
        assert_eq!(encode_message_size(255), [0, 0, 0, 0, 255]);
        assert_eq!(encode_message_size(256), [0, 0, 0, 1, 0]);
        assert_eq!(encode_message_size(257), [0, 0, 0, 1, 1]);
        assert_eq!(encode_message_size(4311810305), [1, 1, 1, 1, 1]);
        assert_eq!(encode_message_size(4328719365), [1, 2, 3, 4, 5]);
        assert_eq!(encode_message_size(47362409218), [11, 7, 5, 3, 2]);
        assert_eq!(
            encode_message_size(1099511627775),
            [255, 255, 255, 255, 255]
        );
    }

    /// Test the message size portion decoding.
    #[test]
    fn test_decode_message_size() {
        assert_eq!(decode_message_size(&[0, 0, 0, 0, 0]), 0);
        assert_eq!(decode_message_size(&[0, 0, 0, 0, 1]), 1);
        assert_eq!(decode_message_size(&[0, 0, 0, 0, 255]), 255);
        assert_eq!(decode_message_size(&[0, 0, 0, 1, 0]), 256);
        assert_eq!(decode_message_size(&[0, 0, 0, 1, 1]), 257);
        assert_eq!(decode_message_size(&[1, 1, 1, 1, 1]), 4311810305);
        assert_eq!(decode_message_size(&[1, 2, 3, 4, 5]), 4328719365);
        assert_eq!(decode_message_size(&[11, 7, 5, 3, 2]), 47362409218);
        assert_eq!(
            decode_message_size(&[255, 255, 255, 255, 255]),
            1099511627775
        );
    }

    /// Test server creation and serving.
    #[tokio::test]
    async fn test_server_serve() {
        let (mut server, mut server_event) = Server::<(), ()>::start(SERVER_ADDR).await.unwrap();
        sleep!();

        println!("Server address: {}", server.get_addr().await.unwrap());
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_event.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(matches!(server_event.next().await, None));
        sleep!();
    }

    /// Test getting server and client addresses.
    #[tokio::test]
    async fn test_addresses() {
        let (mut server, mut server_event) = Server::<(), ()>::start(SERVER_ADDR).await.unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (mut client, mut client_event) = Client::<(), ()>::connect(server_addr).await.unwrap();
        sleep!();

        let client_addr = client.get_addr().await.unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_event.next().await.unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        assert_eq!(
            server.get_addr().await.unwrap(),
            client.get_server_addr().await.unwrap()
        );
        assert_eq!(
            client.get_addr().await.unwrap(),
            server.get_client_addr(0).await.unwrap()
        );
        sleep!();

        client.disconnect().await.unwrap();
        let disconnect_event = client_event.next().await.unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_event.next().await.unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_event.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(matches!(client_event.next().await, None));
        assert!(matches!(server_event.next().await, None));
        sleep!();
    }

    /// Test sending messages between server and client.
    #[tokio::test]
    async fn test_send() {
        let (mut server, mut server_event) =
            Server::<usize, String>::start(SERVER_ADDR).await.unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (mut client, mut client_event) =
            Client::<String, usize>::connect(server_addr).await.unwrap();
        sleep!();

        let client_addr = client.get_addr().await.unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_event.next().await.unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        let msg_from_server = 29275;
        server.send_all(msg_from_server).await.unwrap();
        sleep!();

        let client_recv_event_1 = client_event.next().await.unwrap();
        match client_recv_event_1 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, msg_from_server);
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        let msg_from_client = "Hello, server!".to_owned();
        client.send(msg_from_client.clone()).await.unwrap();
        sleep!();

        let server_recv_event = server_event.next().await.unwrap();
        match server_recv_event {
            ServerEvent::Receive { client_id, data } => {
                assert_eq!(client_id, 0);
                assert_eq!(data, msg_from_client);
                server.send(client_id, data.len()).await.unwrap();
            }
            event => panic!("expected receive event on server, instead got {:?}", event),
        }
        sleep!();

        let client_recv_event_2 = client_event.next().await.unwrap();
        match client_recv_event_2 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, msg_from_client.len());
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        client.disconnect().await.unwrap();
        let disconnect_event = client_event.next().await.unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_event.next().await.unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_event.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(matches!(client_event.next().await, None));
        assert!(matches!(server_event.next().await, None));
        sleep!();
    }

    /// Test sending large random messages between server and client.
    #[tokio::test]
    async fn test_large_send() {
        let (mut server, mut server_event) =
            Server::<u128, u128>::start(SERVER_ADDR).await.unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (mut client, mut client_event) =
            Client::<u128, u128>::connect(server_addr).await.unwrap();
        sleep!();

        let client_addr = client.get_addr().await.unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_event.next().await.unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        let large_msg_from_server: u128 = rand::random();
        let large_msg_from_client: u128 = rand::random();
        println!("Large message from server: {}", large_msg_from_server);
        println!("Large message from client: {}", large_msg_from_client);

        server.send_all(large_msg_from_server).await.unwrap();
        sleep!();

        let client_large_msg_event = client_event.next().await.unwrap();
        match client_large_msg_event {
            ClientEvent::Receive { data } => {
                assert_eq!(data, large_msg_from_server);
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        client.send(large_msg_from_client).await.unwrap();
        sleep!();

        let server_large_msg_event = server_event.next().await.unwrap();
        match server_large_msg_event {
            ServerEvent::Receive { client_id, data } => {
                assert_eq!(client_id, 0);
                assert_eq!(data, large_msg_from_client);
            }
            event => panic!("expected receive event on server, instead got {:?}", event),
        }
        sleep!();

        client.disconnect().await.unwrap();
        let disconnect_event = client_event.next().await.unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_event.next().await.unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_event.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(matches!(client_event.next().await, None));
        assert!(matches!(server_event.next().await, None));
        sleep!();
    }

    /// Test having multiple clients connected, and process events from them individually.
    #[tokio::test]
    async fn test_multiple_clients() {
        let (mut server, mut server_event) =
            Server::<usize, String>::start(SERVER_ADDR).await.unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (mut client_1, mut client_event_1) =
            Client::<String, usize>::connect(server_addr).await.unwrap();
        sleep!();

        let client_addr_1 = client_1.get_addr().await.unwrap();
        println!("Client 1 address: {}", client_addr_1);
        sleep!();

        let client_connect_event_1 = server_event.next().await.unwrap();
        assert!(matches!(
            client_connect_event_1,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        assert_eq!(
            server.get_addr().await.unwrap(),
            client_1.get_server_addr().await.unwrap()
        );
        assert_eq!(
            client_1.get_addr().await.unwrap(),
            server.get_client_addr(0).await.unwrap()
        );
        sleep!();

        let (mut client_2, mut client_event_2) =
            Client::<String, usize>::connect(server_addr).await.unwrap();
        sleep!();

        let client_addr_2 = client_2.get_addr().await.unwrap();
        println!("Client 2 address: {}", client_addr_2);
        sleep!();

        let client_connect_event_2 = server_event.next().await.unwrap();
        assert!(matches!(
            client_connect_event_2,
            ServerEvent::Connect { client_id: 1 }
        ));
        sleep!();

        assert_eq!(
            server.get_addr().await.unwrap(),
            client_2.get_server_addr().await.unwrap()
        );
        assert_eq!(
            client_2.get_addr().await.unwrap(),
            server.get_client_addr(1).await.unwrap()
        );
        sleep!();

        let msg_from_client_1 = "Hello from client 1".to_owned();
        client_1.send(msg_from_client_1.clone()).await.unwrap();
        sleep!();

        let server_msg_from_client_1 = server_event.next().await.unwrap();
        match server_msg_from_client_1 {
            ServerEvent::Receive { client_id, data } => {
                assert_eq!(client_id, 0);
                assert_eq!(data, msg_from_client_1);
                server.send(client_id, data.len()).await.unwrap();
            }
            event => panic!("expected receive event on server, instead got {:?}", event),
        }
        sleep!();

        let server_reply_event_1 = client_event_1.next().await.unwrap();
        match server_reply_event_1 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, msg_from_client_1.len());
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        let msg_from_client_2 = "Hello from client 2".to_owned();
        client_2.send(msg_from_client_2.clone()).await.unwrap();
        sleep!();

        let server_msg_from_client_2 = server_event.next().await.unwrap();
        match server_msg_from_client_2 {
            ServerEvent::Receive { client_id, data } => {
                assert_eq!(client_id, 1);
                assert_eq!(data, msg_from_client_2);
                server.send(client_id, data.len()).await.unwrap();
            }
            event => panic!("expected receive event on server, instead got {:?}", event),
        }
        sleep!();

        let server_reply_event_2 = client_event_2.next().await.unwrap();
        match server_reply_event_2 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, msg_from_client_2.len());
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        let msg_from_server = 29275;
        server.send_all(msg_from_server.clone()).await.unwrap();
        sleep!();

        let server_msg_1 = client_event_1.next().await.unwrap();
        match server_msg_1 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, msg_from_server);
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        let server_msg_2 = client_event_2.next().await.unwrap();
        match server_msg_2 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, msg_from_server);
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        client_1.disconnect().await.unwrap();
        let disconnect_event_1 = client_event_1.next().await.unwrap();
        assert!(matches!(disconnect_event_1, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event_1 = server_event.next().await.unwrap();
        assert!(matches!(
            client_disconnect_event_1,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        client_2.disconnect().await.unwrap();
        let disconnect_event_2 = client_event_2.next().await.unwrap();
        assert!(matches!(disconnect_event_2, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event_2 = server_event.next().await.unwrap();
        assert!(matches!(
            client_disconnect_event_2,
            ServerEvent::Disconnect { client_id: 1 }
        ));
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_event.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(matches!(client_event_1.next().await, None));
        assert!(matches!(client_event_2.next().await, None));
        assert!(matches!(server_event.next().await, None));
        sleep!();
    }

    /// Test removing a client from the server.
    #[tokio::test]
    async fn test_remove_client() {
        let (mut server, mut server_event) = Server::<(), ()>::start(SERVER_ADDR).await.unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (mut client, mut client_event) = Client::<(), ()>::connect(server_addr).await.unwrap();
        sleep!();

        let client_addr = client.get_addr().await.unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_event.next().await.unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        server.remove_client(0).await.unwrap();
        sleep!();

        let disconnect_event = client_event.next().await.unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_event.next().await.unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_event.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(matches!(client_event.next().await, None));
        assert!(matches!(server_event.next().await, None));
        sleep!();
    }

    /// Test stopping a server while a client is connected.
    #[tokio::test]
    async fn test_stop_server_while_client_connected() {
        let (mut server, mut server_event) = Server::<(), ()>::start(SERVER_ADDR).await.unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (mut client, mut client_event) = Client::<(), ()>::connect(server_addr).await.unwrap();
        sleep!();

        let client_addr = client.get_addr().await.unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_event.next().await.unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_event.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        let disconnect_event = client_event.next().await.unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        assert!(matches!(client_event.next().await, None));
        assert!(matches!(server_event.next().await, None));
        sleep!();
    }
}
