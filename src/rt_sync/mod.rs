//! # The Synchronous Implementation
//!
//! This includes an implementation of the protocol for a synchronous environment.
//!
//! ## Creating a server
//!
//! A server can be built using the `Server` implementation:
//!
//! ```no_run
//! use rustdtp::rt_sync::*;
//!
//! fn main() {
//!     // Create a server that receives strings and returns the length of each string
//!     let (server, mut server_event) = Server::<usize, String>::start(("0.0.0.0", 0)).unwrap();
//!
//!     // Iterate over events
//!     while let Some(event) = server_event.next() {
//!         match event {
//!             ServerEvent::Connect { client_id } => {
//!                 println!("Client with ID {} connected", client_id);
//!             }
//!             ServerEvent::Disconnect { client_id } => {
//!                 println!("Client with ID {} disconnected", client_id);
//!             }
//!             ServerEvent::Receive { client_id, data } => {
//!                 // Send back the length of the string
//!                 server.send(client_id, data.len()).unwrap();
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
//! use rustdtp::rt_sync::*;
//!
//! fn main() {
//!     // Create a client that sends a message to the server and receives the length of the message
//!     let (client, mut client_event) = Client::<String, usize>::connect(("127.0.0.1", 29275)).unwrap();
//!
//!     // Send a message to the server
//!     let msg = "Hello, server!".to_owned();
//!     client.send(msg.clone()).unwrap();
//!
//!     // Receive the response
//!     match client_event.next().unwrap() {
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

mod client;
mod command_channel;
mod event_iter;
mod server;

/// Types exported from the crate.
pub use client::{Client, ClientEvent, ClientHandle};
pub use event_iter::EventIter;
pub use server::{Server, ServerEvent, ServerHandle};

/// Tests using the synchronous API.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::util::*;
    use rand;
    use serde::{Deserialize, Serialize};

    /// Default amount of time to sleep, in milliseconds.
    const SLEEP_TIME: u64 = 100;

    /// Default server address.
    const SERVER_ADDR: (&'static str, u16) = ("127.0.0.1", 0);

    /// Sleep for a desired duration.
    macro_rules! sleep {
        () => {
            ::std::thread::sleep(::std::time::Duration::from_millis(SLEEP_TIME))
        };
        ($x:expr) => {
            ::std::thread::sleep(::std::time::Duration::from_millis($x))
        };
    }

    /// A custom type.
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct Custom {
        pub a: i32,
        pub b: String,
        pub c: Vec<String>,
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

    /// Test crypto functions.
    #[test]
    fn test_crypto() {
        let rsa_message = "Hello, RSA!";
        let (public_key, private_key) = crypto::rsa_keys().unwrap();
        let rsa_encrypted = crypto::rsa_encrypt(&public_key, rsa_message.as_bytes()).unwrap();
        let rsa_decrypted = crypto::rsa_decrypt(&private_key, &rsa_encrypted).unwrap();
        let rsa_decrypted_message = std::str::from_utf8(&rsa_decrypted).unwrap();
        assert_eq!(rsa_decrypted_message, rsa_message);
        assert_ne!(rsa_encrypted, rsa_message.as_bytes());

        let aes_message = "Hello, AES!";
        let key = crypto::aes_key();
        let aes_encrypted = crypto::aes_encrypt(&key, aes_message.as_bytes()).unwrap();
        let aes_decrypted = crypto::aes_decrypt(&key, &aes_encrypted).unwrap();
        let aes_decrypted_message = std::str::from_utf8(&aes_decrypted).unwrap();
        assert_eq!(aes_decrypted_message, aes_message);
        assert_ne!(aes_encrypted, aes_message.as_bytes());

        let encrypted_key = crypto::rsa_encrypt(&public_key, &key).unwrap();
        let decrypted_key = crypto::rsa_decrypt(&private_key, &encrypted_key).unwrap();
        assert_eq!(decrypted_key, key);
        assert_ne!(encrypted_key, key);
    }

    /// Test server creation and serving.
    #[test]
    fn test_server_serve() {
        let (server, mut server_event) = Server::<(), ()>::start(SERVER_ADDR).unwrap();
        sleep!();

        println!("Server address: {}", server.get_addr().unwrap());
        sleep!();

        server.stop().unwrap();
        let stop_event = server_event.next().unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(matches!(server_event.next(), None));
        sleep!();
    }

    /// Test getting server and client addresses.
    #[test]
    fn test_addresses() {
        let (server, mut server_event) = Server::<(), ()>::start(SERVER_ADDR).unwrap();
        sleep!();

        let server_addr = server.get_addr().unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (client, mut client_event) = Client::<(), ()>::connect(server_addr).unwrap();
        sleep!();

        let client_addr = client.get_addr().unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_event.next().unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        assert_eq!(
            server.get_addr().unwrap(),
            client.get_server_addr().unwrap()
        );
        assert_eq!(
            client.get_addr().unwrap(),
            server.get_client_addr(0).unwrap()
        );
        sleep!();

        client.disconnect().unwrap();
        let disconnect_event = client_event.next().unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_event.next().unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().unwrap();
        let stop_event = server_event.next().unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(matches!(client_event.next(), None));
        assert!(matches!(server_event.next(), None));
        sleep!();
    }

    /// Test sending messages between server and client.
    #[test]
    fn test_send() {
        let (server, mut server_event) = Server::<usize, String>::start(SERVER_ADDR).unwrap();
        sleep!();

        let server_addr = server.get_addr().unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (client, mut client_event) = Client::<String, usize>::connect(server_addr).unwrap();
        sleep!();

        let client_addr = client.get_addr().unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_event.next().unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        let msg_from_server = 29275;
        server.send_all(msg_from_server).unwrap();
        sleep!();

        let client_recv_event_1 = client_event.next().unwrap();
        match client_recv_event_1 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, msg_from_server);
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        let msg_from_client = "Hello, server!".to_owned();
        client.send(msg_from_client.clone()).unwrap();
        sleep!();

        let server_recv_event = server_event.next().unwrap();
        match server_recv_event {
            ServerEvent::Receive { client_id, data } => {
                assert_eq!(client_id, 0);
                assert_eq!(data, msg_from_client);
                server.send(client_id, data.len()).unwrap();
            }
            event => panic!("expected receive event on server, instead got {:?}", event),
        }
        sleep!();

        let client_recv_event_2 = client_event.next().unwrap();
        match client_recv_event_2 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, msg_from_client.len());
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        client.disconnect().unwrap();
        let disconnect_event = client_event.next().unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_event.next().unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().unwrap();
        let stop_event = server_event.next().unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(matches!(client_event.next(), None));
        assert!(matches!(server_event.next(), None));
        sleep!();
    }

    /// Test sending large random messages between server and client.
    #[test]
    fn test_large_send() {
        let (server, mut server_event) = Server::<u128, u128>::start(SERVER_ADDR).unwrap();
        sleep!();

        let server_addr = server.get_addr().unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (client, mut client_event) = Client::<u128, u128>::connect(server_addr).unwrap();
        sleep!();

        let client_addr = client.get_addr().unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_event.next().unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        let large_msg_from_server: u128 = rand::random();
        let large_msg_from_client: u128 = rand::random();
        println!("Large message from server: {}", large_msg_from_server);
        println!("Large message from client: {}", large_msg_from_client);

        server.send_all(large_msg_from_server).unwrap();
        sleep!();

        let client_large_msg_event = client_event.next().unwrap();
        match client_large_msg_event {
            ClientEvent::Receive { data } => {
                assert_eq!(data, large_msg_from_server);
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        client.send(large_msg_from_client).unwrap();
        sleep!();

        let server_large_msg_event = server_event.next().unwrap();
        match server_large_msg_event {
            ServerEvent::Receive { client_id, data } => {
                assert_eq!(client_id, 0);
                assert_eq!(data, large_msg_from_client);
            }
            event => panic!("expected receive event on server, instead got {:?}", event),
        }
        sleep!();

        client.disconnect().unwrap();
        let disconnect_event = client_event.next().unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_event.next().unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().unwrap();
        let stop_event = server_event.next().unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(matches!(client_event.next(), None));
        assert!(matches!(server_event.next(), None));
        sleep!();
    }

    /// Test sending numerous messages
    #[test]
    fn test_sending_numerous_messages() {
        let (server, mut server_event) = Server::<u16, u16>::start(SERVER_ADDR).unwrap();
        sleep!();

        let server_addr = server.get_addr().unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (client, mut client_event) = Client::<u16, u16>::connect(server_addr).unwrap();
        sleep!();

        let client_addr = client.get_addr().unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_event.next().unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        let num_server_messages: usize = (rand::random::<usize>() % 64) + 64;
        let num_client_messages: usize = (rand::random::<usize>() % 128) + 128;
        let server_messages: Vec<u16> = vec![rand::random::<u16>() % 1024; num_server_messages];
        let client_messages: Vec<u16> = vec![rand::random::<u16>() % 1024; num_client_messages];
        println!("Generated {} server messages", num_server_messages);
        println!("Generated {} client messages", num_client_messages);

        for &server_message in &server_messages {
            client.send(server_message).unwrap();
        }
        for &client_message in &client_messages {
            server.send_all(client_message).unwrap();
        }
        sleep!();

        for &server_message in &server_messages {
            let server_recv_event = server_event.next().unwrap();
            match server_recv_event {
                ServerEvent::Receive { client_id, data } => {
                    assert_eq!(client_id, 0);
                    assert_eq!(data, server_message);
                }
                event => panic!("expected receive event on server, instead got {:?}", event),
            }
        }

        for &client_message in &client_messages {
            let client_recv_event = client_event.next().unwrap();
            match client_recv_event {
                ClientEvent::Receive { data } => {
                    assert_eq!(data, client_message);
                }
                event => panic!("expected receive event on client, instead got {:?}", event),
            }
        }

        client.disconnect().unwrap();
        let disconnect_event = client_event.next().unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_event.next().unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().unwrap();
        let stop_event = server_event.next().unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(matches!(client_event.next(), None));
        assert!(matches!(server_event.next(), None));
        sleep!();
    }

    /// Test sending custom types
    #[test]
    fn test_sending_custom_types() {
        let (server, mut server_event) = Server::<Custom, Custom>::start(SERVER_ADDR).unwrap();
        sleep!();

        let server_addr = server.get_addr().unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (client, mut client_event) = Client::<Custom, Custom>::connect(server_addr).unwrap();
        sleep!();

        let client_addr = client.get_addr().unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_event.next().unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        let server_message = Custom {
            a: 123,
            b: "Hello, custom server class!".to_owned(),
            c: vec![
                "first server item".to_owned(),
                "second server item".to_owned(),
            ],
        };
        let client_message = Custom {
            a: 456,
            b: "Hello, custom client class!".to_owned(),
            c: vec![
                "#1 client item".to_owned(),
                "client item #2".to_owned(),
                "(3) client item".to_owned(),
            ],
        };

        server.send_all(client_message.clone()).unwrap();
        sleep!();

        let client_recv_event_1 = client_event.next().unwrap();
        match client_recv_event_1 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, client_message);
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        client.send(server_message.clone()).unwrap();
        sleep!();

        let server_recv_event = server_event.next().unwrap();
        match server_recv_event {
            ServerEvent::Receive { client_id, data } => {
                assert_eq!(client_id, 0);
                assert_eq!(data, server_message);
            }
            event => panic!("expected receive event on server, instead got {:?}", event),
        }
        sleep!();

        client.disconnect().unwrap();
        let disconnect_event = client_event.next().unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_event.next().unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().unwrap();
        let stop_event = server_event.next().unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(matches!(client_event.next(), None));
        assert!(matches!(server_event.next(), None));
        sleep!();
    }

    /// Test having multiple clients connected, and process events from them individually.
    #[test]
    fn test_multiple_clients() {
        let (server, mut server_event) = Server::<usize, String>::start(SERVER_ADDR).unwrap();
        sleep!();

        let server_addr = server.get_addr().unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (client_1, mut client_event_1) = Client::<String, usize>::connect(server_addr).unwrap();
        sleep!();

        let client_addr_1 = client_1.get_addr().unwrap();
        println!("Client 1 address: {}", client_addr_1);
        sleep!();

        let client_connect_event_1 = server_event.next().unwrap();
        assert!(matches!(
            client_connect_event_1,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        assert_eq!(
            server.get_addr().unwrap(),
            client_1.get_server_addr().unwrap()
        );
        assert_eq!(
            client_1.get_addr().unwrap(),
            server.get_client_addr(0).unwrap()
        );
        sleep!();

        let (client_2, mut client_event_2) = Client::<String, usize>::connect(server_addr).unwrap();
        sleep!();

        let client_addr_2 = client_2.get_addr().unwrap();
        println!("Client 2 address: {}", client_addr_2);
        sleep!();

        let client_connect_event_2 = server_event.next().unwrap();
        assert!(matches!(
            client_connect_event_2,
            ServerEvent::Connect { client_id: 1 }
        ));
        sleep!();

        assert_eq!(
            server.get_addr().unwrap(),
            client_2.get_server_addr().unwrap()
        );
        assert_eq!(
            client_2.get_addr().unwrap(),
            server.get_client_addr(1).unwrap()
        );
        sleep!();

        let msg_from_client_1 = "Hello from client 1".to_owned();
        client_1.send(msg_from_client_1.clone()).unwrap();
        sleep!();

        let server_msg_from_client_1 = server_event.next().unwrap();
        match server_msg_from_client_1 {
            ServerEvent::Receive { client_id, data } => {
                assert_eq!(client_id, 0);
                assert_eq!(data, msg_from_client_1);
                server.send(client_id, data.len()).unwrap();
            }
            event => panic!("expected receive event on server, instead got {:?}", event),
        }
        sleep!();

        let server_reply_event_1 = client_event_1.next().unwrap();
        match server_reply_event_1 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, msg_from_client_1.len());
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        let msg_from_client_2 = "Hello from client 2".to_owned();
        client_2.send(msg_from_client_2.clone()).unwrap();
        sleep!();

        let server_msg_from_client_2 = server_event.next().unwrap();
        match server_msg_from_client_2 {
            ServerEvent::Receive { client_id, data } => {
                assert_eq!(client_id, 1);
                assert_eq!(data, msg_from_client_2);
                server.send(client_id, data.len()).unwrap();
            }
            event => panic!("expected receive event on server, instead got {:?}", event),
        }
        sleep!();

        let server_reply_event_2 = client_event_2.next().unwrap();
        match server_reply_event_2 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, msg_from_client_2.len());
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        let msg_from_server = 29275;
        server.send_all(msg_from_server.clone()).unwrap();
        sleep!();

        let server_msg_1 = client_event_1.next().unwrap();
        match server_msg_1 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, msg_from_server);
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        let server_msg_2 = client_event_2.next().unwrap();
        match server_msg_2 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, msg_from_server);
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        client_1.disconnect().unwrap();
        let disconnect_event_1 = client_event_1.next().unwrap();
        assert!(matches!(disconnect_event_1, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event_1 = server_event.next().unwrap();
        assert!(matches!(
            client_disconnect_event_1,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        client_2.disconnect().unwrap();
        let disconnect_event_2 = client_event_2.next().unwrap();
        assert!(matches!(disconnect_event_2, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event_2 = server_event.next().unwrap();
        assert!(matches!(
            client_disconnect_event_2,
            ServerEvent::Disconnect { client_id: 1 }
        ));
        sleep!();

        server.stop().unwrap();
        let stop_event = server_event.next().unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(matches!(client_event_1.next(), None));
        assert!(matches!(client_event_2.next(), None));
        assert!(matches!(server_event.next(), None));
        sleep!();
    }

    /// Test removing a client from the server.
    #[test]
    fn test_remove_client() {
        let (server, mut server_event) = Server::<(), ()>::start(SERVER_ADDR).unwrap();
        sleep!();

        let server_addr = server.get_addr().unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (client, mut client_event) = Client::<(), ()>::connect(server_addr).unwrap();
        sleep!();

        let client_addr = client.get_addr().unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_event.next().unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        server.remove_client(0).unwrap();
        sleep!();

        let disconnect_event = client_event.next().unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_event.next().unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().unwrap();
        let stop_event = server_event.next().unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(matches!(client_event.next(), None));
        assert!(matches!(server_event.next(), None));
        sleep!();
    }

    /// Test stopping a server while a client is connected.
    #[test]
    fn test_stop_server_while_client_connected() {
        let (server, mut server_event) = Server::<(), ()>::start(SERVER_ADDR).unwrap();
        sleep!();

        let server_addr = server.get_addr().unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (client, mut client_event) = Client::<(), ()>::connect(server_addr).unwrap();
        sleep!();

        let client_addr = client.get_addr().unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_event.next().unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        server.stop().unwrap();
        let stop_event = server_event.next().unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        let disconnect_event = client_event.next().unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        assert!(matches!(client_event.next(), None));
        assert!(matches!(server_event.next(), None));
        sleep!();
    }
}
