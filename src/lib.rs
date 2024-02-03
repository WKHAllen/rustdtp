//! # Data Transfer Protocol for Rust
//!
//! Cross-platform networking interfaces for Rust.
//!
//! ## Data Transfer Protocol
//!
//! The Data Transfer Protocol (DTP) is a larger project to make ergonomic network programming available in any language. See the full project [here](https://wkhallen.com/dtp/).
//!
//! ## Installation
//!
//! Add the package in `Cargo.toml`:
//!
//! ```toml
//! rustdtp = "0.5"
//! ```
//!
//! ## Creating a server
//!
//! A server can be built using the `Server` implementation:
//!
//! ```no_run
//! use rustdtp::*;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create a server that receives strings and returns the length of each string
//!     let (mut server, mut server_events) = Server::builder()
//!         .sending::<usize>()
//!         .receiving::<String>()
//!         .with_event_channel()
//!         .start(("0.0.0.0", 0))
//!         .await
//!         .unwrap();
//!
//!     // Iterate over events
//!     while let Some(event) = server_events.next().await {
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
//! use rustdtp::*;
//!
//! #[tokio::main]
//! async fn main() {
//!     // Create a client that sends a message to the server and receives the length of the message
//!     let (mut client, mut client_events) = Client::builder()
//!         .sending::<String>()
//!         .receiving::<usize>()
//!         .with_event_channel()
//!         .connect(("127.0.0.1", 29275))
//!         .await
//!         .unwrap();
//!
//!     // Send a message to the server
//!     let msg = "Hello, server!".to_owned();
//!     client.send(msg.clone()).await.unwrap();
//!
//!     // Receive the response
//!     match client_events.next().await.unwrap() {
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
//! ## Security
//!
//! Information security comes included. Every message sent over a network interface is encrypted with AES-256. Key exchanges are performed using a 2048-bit RSA key-pair.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

mod client;
mod command_channel;
mod crypto;
mod event_stream;
mod server;
mod timeout;
mod util;

// Types re-exported from the crate.
pub use async_trait::async_trait;
pub use tokio_stream::StreamExt as EventStreamExt;

// Types exported from the crate.
pub use client::{
    Client, ClientBuilder, ClientEvent, ClientEventCallbacks, ClientEventHandler, ClientHandle,
};
pub use event_stream::EventStream;
pub use server::{
    Server, ServerBuilder, ServerEvent, ServerEventCallbacks, ServerEventHandler, ServerHandle,
};

/// Root-level tests.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::util::*;
    use async_trait::async_trait;
    use serde::de::DeserializeOwned;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use tokio::sync::mpsc::{channel, Sender};

    /// Default amount of time to sleep, in milliseconds.
    const SLEEP_TIME: u64 = 100;

    /// Default server address.
    const SERVER_ADDR: (&str, u16) = ("127.0.0.1", 0);

    /// Default channel size.
    const DEFAULT_CHANNEL_SIZE: usize = 1000;

    /// Sleep for a desired duration.
    macro_rules! sleep {
        () => {
            ::tokio::time::sleep(::tokio::time::Duration::from_millis(SLEEP_TIME)).await
        };
        ($x:expr) => {
            ::tokio::time::sleep(::tokio::time::Duration::from_millis($x)).await
        };
    }

    /// A custom type.
    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct Custom {
        pub a: i32,
        pub b: String,
        pub c: Vec<String>,
    }

    /// Statically assert that a type implements a trait or lifetime.
    macro_rules! assert_impl {
        ($name:ty, $trait_name:path) => {{
            fn __test_impl__<T: $trait_name>() {}
            __test_impl__::<$name>()
        }};
        ($name:ty, $lifetime_name:lifetime) => {{
            fn __test_impl__<T: $lifetime_name>() {}
            __test_impl__::<$name>()
        }};
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
    #[tokio::test]
    async fn test_crypto() {
        let rsa_message = "Hello, RSA!";
        let (public_key, private_key) = crypto::rsa_keys().await.unwrap();
        let rsa_encrypted = Arc::<[u8]>::from(
            crypto::rsa_encrypt(public_key.clone(), rsa_message.as_bytes().into())
                .await
                .unwrap(),
        );
        let rsa_decrypted = crypto::rsa_decrypt(private_key.clone(), Arc::clone(&rsa_encrypted))
            .await
            .unwrap();
        let rsa_decrypted_message = std::str::from_utf8(&rsa_decrypted).unwrap();
        assert_eq!(rsa_decrypted_message, rsa_message);
        assert_ne!(&*rsa_encrypted, rsa_message.as_bytes());

        let aes_message = "Hello, AES!";
        let key = crypto::aes_key().await;
        let aes_encrypted = Arc::<[u8]>::from(
            crypto::aes_encrypt(key, aes_message.as_bytes().into())
                .await
                .unwrap(),
        );
        let aes_decrypted = crypto::aes_decrypt(key, Arc::clone(&aes_encrypted))
            .await
            .unwrap();
        let aes_decrypted_message = std::str::from_utf8(&aes_decrypted).unwrap();
        assert_eq!(aes_decrypted_message, aes_message);
        assert_ne!(&*aes_encrypted, aes_message.as_bytes());

        let encrypted_key =
            Arc::<[u8]>::from(crypto::rsa_encrypt(public_key, key.into()).await.unwrap());
        let decrypted_key = crypto::rsa_decrypt(private_key, Arc::clone(&encrypted_key))
            .await
            .unwrap();
        assert_eq!(decrypted_key, key);
        assert_ne!(&*encrypted_key, key);
    }

    /// Test server creation and serving.
    #[tokio::test]
    async fn test_server_serve() {
        let (mut server, mut server_events) = Server::<(), ()>::start(SERVER_ADDR).await.unwrap();
        sleep!();

        println!("Server address: {}", server.get_addr().await.unwrap());
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_events.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(server_events.next().await.is_none());
        sleep!();
    }

    /// Test getting server and client addresses.
    #[tokio::test]
    async fn test_addresses() {
        let (mut server, mut server_events) = Server::<(), ()>::start(SERVER_ADDR).await.unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (mut client, mut client_events) = Client::<(), ()>::connect(server_addr).await.unwrap();
        sleep!();

        let client_addr = client.get_addr().await.unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_events.next().await.unwrap();
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
        let disconnect_event = client_events.next().await.unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_events.next().await.unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_events.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(client_events.next().await.is_none());
        assert!(server_events.next().await.is_none());
        sleep!();
    }

    /// Test sending messages between server and client.
    #[tokio::test]
    async fn test_send() {
        let (mut server, mut server_events) =
            Server::<usize, String>::start(SERVER_ADDR).await.unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (mut client, mut client_events) =
            Client::<String, usize>::connect(server_addr).await.unwrap();
        sleep!();

        let client_addr = client.get_addr().await.unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_events.next().await.unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        let msg_from_server = 29275;
        server.send_all(msg_from_server).await.unwrap();
        sleep!();

        let client_recv_event_1 = client_events.next().await.unwrap();
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

        let server_recv_event = server_events.next().await.unwrap();
        match server_recv_event {
            ServerEvent::Receive { client_id, data } => {
                assert_eq!(client_id, 0);
                assert_eq!(data, msg_from_client);
                server.send(client_id, data.len()).await.unwrap();
            }
            event => panic!("expected receive event on server, instead got {:?}", event),
        }
        sleep!();

        let client_recv_event_2 = client_events.next().await.unwrap();
        match client_recv_event_2 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, msg_from_client.len());
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        client.disconnect().await.unwrap();
        let disconnect_event = client_events.next().await.unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_events.next().await.unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_events.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(client_events.next().await.is_none());
        assert!(server_events.next().await.is_none());
        sleep!();
    }

    /// Test sending large random messages between server and client.
    #[tokio::test]
    async fn test_large_send() {
        let (mut server, mut server_events) =
            Server::<u128, u128>::start(SERVER_ADDR).await.unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (mut client, mut client_events) =
            Client::<u128, u128>::connect(server_addr).await.unwrap();
        sleep!();

        let client_addr = client.get_addr().await.unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_events.next().await.unwrap();
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

        let client_large_msg_event = client_events.next().await.unwrap();
        match client_large_msg_event {
            ClientEvent::Receive { data } => {
                assert_eq!(data, large_msg_from_server);
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        client.send(large_msg_from_client).await.unwrap();
        sleep!();

        let server_large_msg_event = server_events.next().await.unwrap();
        match server_large_msg_event {
            ServerEvent::Receive { client_id, data } => {
                assert_eq!(client_id, 0);
                assert_eq!(data, large_msg_from_client);
            }
            event => panic!("expected receive event on server, instead got {:?}", event),
        }
        sleep!();

        client.disconnect().await.unwrap();
        let disconnect_event = client_events.next().await.unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_events.next().await.unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_events.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(client_events.next().await.is_none());
        assert!(server_events.next().await.is_none());
        sleep!();
    }

    /// Test sending numerous messages
    #[tokio::test]
    async fn test_sending_numerous_messages() {
        let (mut server, mut server_events) = Server::<u16, u16>::start(SERVER_ADDR).await.unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (mut client, mut client_events) =
            Client::<u16, u16>::connect(server_addr).await.unwrap();
        sleep!();

        let client_addr = client.get_addr().await.unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_events.next().await.unwrap();
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
            client.send(server_message).await.unwrap();
        }
        for &client_message in &client_messages {
            server.send_all(client_message).await.unwrap();
        }
        sleep!();

        for &server_message in &server_messages {
            let server_recv_event = server_events.next().await.unwrap();
            match server_recv_event {
                ServerEvent::Receive { client_id, data } => {
                    assert_eq!(client_id, 0);
                    assert_eq!(data, server_message);
                }
                event => panic!("expected receive event on server, instead got {:?}", event),
            }
        }

        for &client_message in &client_messages {
            let client_recv_event = client_events.next().await.unwrap();
            match client_recv_event {
                ClientEvent::Receive { data } => {
                    assert_eq!(data, client_message);
                }
                event => panic!("expected receive event on client, instead got {:?}", event),
            }
        }

        client.disconnect().await.unwrap();
        let disconnect_event = client_events.next().await.unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_events.next().await.unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_events.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(client_events.next().await.is_none());
        assert!(server_events.next().await.is_none());
        sleep!();
    }

    /// Test sending custom types
    #[tokio::test]
    async fn test_sending_custom_types() {
        let (mut server, mut server_events) =
            Server::<Custom, Custom>::start(SERVER_ADDR).await.unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (mut client, mut client_events) = Client::<Custom, Custom>::connect(server_addr)
            .await
            .unwrap();
        sleep!();

        let client_addr = client.get_addr().await.unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_events.next().await.unwrap();
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

        server.send_all(client_message.clone()).await.unwrap();
        sleep!();

        let client_recv_event_1 = client_events.next().await.unwrap();
        match client_recv_event_1 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, client_message);
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        client.send(server_message.clone()).await.unwrap();
        sleep!();

        let server_recv_event = server_events.next().await.unwrap();
        match server_recv_event {
            ServerEvent::Receive { client_id, data } => {
                assert_eq!(client_id, 0);
                assert_eq!(data, server_message);
            }
            event => panic!("expected receive event on server, instead got {:?}", event),
        }
        sleep!();

        client.disconnect().await.unwrap();
        let disconnect_event = client_events.next().await.unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_events.next().await.unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_events.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(client_events.next().await.is_none());
        assert!(server_events.next().await.is_none());
        sleep!();
    }

    /// Test having multiple clients connected, and process events from them individually.
    #[tokio::test]
    async fn test_multiple_clients() {
        let (mut server, mut server_events) =
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

        let client_connect_event_1 = server_events.next().await.unwrap();
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

        let client_connect_event_2 = server_events.next().await.unwrap();
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

        let server_msg_from_client_1 = server_events.next().await.unwrap();
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

        let server_msg_from_client_2 = server_events.next().await.unwrap();
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
        server.send_all(msg_from_server).await.unwrap();
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

        let client_disconnect_event_1 = server_events.next().await.unwrap();
        assert!(matches!(
            client_disconnect_event_1,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        client_2.disconnect().await.unwrap();
        let disconnect_event_2 = client_event_2.next().await.unwrap();
        assert!(matches!(disconnect_event_2, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event_2 = server_events.next().await.unwrap();
        assert!(matches!(
            client_disconnect_event_2,
            ServerEvent::Disconnect { client_id: 1 }
        ));
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_events.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(client_event_1.next().await.is_none());
        assert!(client_event_2.next().await.is_none());
        assert!(server_events.next().await.is_none());
        sleep!();
    }

    /// Test removing a client from the server.
    #[tokio::test]
    async fn test_remove_client() {
        let (mut server, mut server_events) = Server::<(), ()>::start(SERVER_ADDR).await.unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (mut client, mut client_events) = Client::<(), ()>::connect(server_addr).await.unwrap();
        sleep!();

        let client_addr = client.get_addr().await.unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_events.next().await.unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        server.remove_client(0).await.unwrap();
        sleep!();

        let disconnect_event = client_events.next().await.unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_events.next().await.unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_events.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(client_events.next().await.is_none());
        assert!(server_events.next().await.is_none());
        sleep!();
    }

    /// Test stopping a server while a client is connected.
    #[tokio::test]
    async fn test_stop_server_while_client_connected() {
        let (mut server, mut server_events) = Server::<(), ()>::start(SERVER_ADDR).await.unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (mut client, mut client_events) = Client::<(), ()>::connect(server_addr).await.unwrap();
        sleep!();

        let client_addr = client.get_addr().await.unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_events.next().await.unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_events.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        let disconnect_event = client_events.next().await.unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        assert!(client_events.next().await.is_none());
        assert!(server_events.next().await.is_none());
        sleep!();
    }

    /// Test that returned types implement a desired set of traits.
    #[tokio::test]
    async fn test_impls() {
        type TestType = usize;

        assert_impl!(ServerHandle<TestType>, Send);
        assert_impl!(ServerHandle<TestType>, Sync);
        assert_impl!(ServerHandle<TestType>, 'static);
        assert_impl!(ServerEvent<TestType>, Send);
        assert_impl!(ServerEvent<TestType>, Sync);
        assert_impl!(ServerEvent<TestType>, Clone);
        assert_impl!(ServerEvent<TestType>, 'static);
        assert_impl!(ClientHandle<TestType>, Send);
        assert_impl!(ClientHandle<TestType>, Sync);
        assert_impl!(ClientHandle<TestType>, 'static);
        assert_impl!(ClientEvent<TestType>, Send);
        assert_impl!(ClientEvent<TestType>, Sync);
        assert_impl!(ClientEvent<TestType>, Clone);
        assert_impl!(ClientEvent<TestType>, 'static);
    }

    /// Test builder with callback configuration.
    #[tokio::test]
    async fn test_builder_with_callbacks() {
        let (server_connect_sender, mut server_connect_receiver) = channel(DEFAULT_CHANNEL_SIZE);
        let (server_disconnect_sender, mut server_disconnect_receiver) =
            channel(DEFAULT_CHANNEL_SIZE);
        let (server_receive_sender, mut server_receive_receiver) = channel(DEFAULT_CHANNEL_SIZE);
        let (server_stop_sender, mut server_stop_receiver) = channel(DEFAULT_CHANNEL_SIZE);
        let (client_receive_sender, mut client_receive_receiver) = channel(DEFAULT_CHANNEL_SIZE);
        let (client_disconnect_sender, mut client_disconnect_receiver) =
            channel(DEFAULT_CHANNEL_SIZE);

        let mut server = Server::builder()
            .sending::<usize>()
            .receiving::<String>()
            .with_event_callbacks(
                ServerEventCallbacks::new()
                    .on_connect(move |client_id| {
                        let server_connect_sender = server_connect_sender.clone();
                        async move {
                            server_connect_sender.send(client_id).await.unwrap();
                        }
                    })
                    .on_disconnect(move |client_id| {
                        let server_disconnect_sender = server_disconnect_sender.clone();
                        async move {
                            server_disconnect_sender.send(client_id).await.unwrap();
                        }
                    })
                    .on_receive(move |client_id, data| {
                        let server_receive_sender = server_receive_sender.clone();
                        async move {
                            server_receive_sender.send((client_id, data)).await.unwrap();
                        }
                    })
                    .on_stop(move || {
                        let server_stop_sender = server_stop_sender.clone();
                        async move {
                            server_stop_sender.send(()).await.unwrap();
                        }
                    }),
            )
            .start(SERVER_ADDR)
            .await
            .unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let mut client = Client::builder()
            .sending::<String>()
            .receiving::<usize>()
            .with_event_callbacks(
                ClientEventCallbacks::new()
                    .on_receive(move |data| {
                        let client_receive_sender = client_receive_sender.clone();
                        async move {
                            client_receive_sender.send(data).await.unwrap();
                        }
                    })
                    .on_disconnect(move || {
                        let client_disconnect_sender = client_disconnect_sender.clone();
                        async move {
                            client_disconnect_sender.send(()).await.unwrap();
                        }
                    }),
            )
            .connect(server_addr)
            .await
            .unwrap();
        sleep!();

        let client_addr = client.get_addr().await.unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_connect_receiver.recv().await.unwrap();
        assert_eq!(client_connect_event, 0);
        sleep!();

        let msg_from_server = 29275;
        server.send_all(msg_from_server).await.unwrap();
        sleep!();

        let client_recv_event_1 = client_receive_receiver.recv().await.unwrap();
        assert_eq!(client_recv_event_1, msg_from_server);
        sleep!();

        let msg_from_client = "Hello, server!".to_owned();
        client.send(msg_from_client.clone()).await.unwrap();
        sleep!();

        let server_recv_event = server_receive_receiver.recv().await.unwrap();
        assert_eq!(server_recv_event, (0, msg_from_client.clone()));
        server
            .send(server_recv_event.0, server_recv_event.1.len())
            .await
            .unwrap();
        sleep!();

        let client_recv_event_2 = client_receive_receiver.recv().await.unwrap();
        assert_eq!(client_recv_event_2, msg_from_client.len());
        sleep!();

        client.disconnect().await.unwrap();
        client_disconnect_receiver.recv().await.unwrap();
        sleep!();

        let client_disconnect_event = server_disconnect_receiver.recv().await.unwrap();
        assert_eq!(client_disconnect_event, 0);
        sleep!();

        server.stop().await.unwrap();
        server_stop_receiver.recv().await.unwrap();
        sleep!();

        assert!(server_connect_receiver.try_recv().is_err());
        assert!(server_disconnect_receiver.try_recv().is_err());
        assert!(server_receive_receiver.try_recv().is_err());
        assert!(server_stop_receiver.try_recv().is_err());
        assert!(client_receive_receiver.try_recv().is_err());
        assert!(client_disconnect_receiver.try_recv().is_err());
        sleep!();
    }

    /// Test builder with handler configuration.
    #[tokio::test]
    async fn test_builder_with_handler_config() {
        struct ServerHandler<R>
        where
            R: DeserializeOwned + Send + 'static,
        {
            connect_sender: Sender<usize>,
            disconnect_sender: Sender<usize>,
            receive_sender: Sender<(usize, R)>,
            stop_sender: Sender<()>,
        }

        impl<R> ServerHandler<R>
        where
            R: DeserializeOwned + Send + 'static,
        {
            pub fn new(
                connect_sender: Sender<usize>,
                disconnect_sender: Sender<usize>,
                receive_sender: Sender<(usize, R)>,
                stop_sender: Sender<()>,
            ) -> Self {
                Self {
                    connect_sender,
                    disconnect_sender,
                    receive_sender,
                    stop_sender,
                }
            }
        }

        #[async_trait]
        impl<R> ServerEventHandler<R> for ServerHandler<R>
        where
            R: DeserializeOwned + Send + 'static,
        {
            async fn on_connect(&self, client_id: usize) {
                self.connect_sender.send(client_id).await.unwrap();
            }

            async fn on_disconnect(&self, client_id: usize) {
                self.disconnect_sender.send(client_id).await.unwrap();
            }

            async fn on_receive(&self, client_id: usize, data: R) {
                self.receive_sender.send((client_id, data)).await.unwrap();
            }

            async fn on_stop(&self) {
                self.stop_sender.send(()).await.unwrap();
            }
        }

        struct ClientHandler<R>
        where
            R: DeserializeOwned + Send + 'static,
        {
            receive_sender: Sender<R>,
            disconnect_sender: Sender<()>,
        }

        impl<R> ClientHandler<R>
        where
            R: DeserializeOwned + Send + 'static,
        {
            pub fn new(receive_sender: Sender<R>, disconnect_sender: Sender<()>) -> Self {
                Self {
                    receive_sender,
                    disconnect_sender,
                }
            }
        }

        #[async_trait]
        impl<R> ClientEventHandler<R> for ClientHandler<R>
        where
            R: DeserializeOwned + Send + 'static,
        {
            async fn on_receive(&self, data: R) {
                self.receive_sender.send(data).await.unwrap();
            }

            async fn on_disconnect(&self) {
                self.disconnect_sender.send(()).await.unwrap();
            }
        }

        let (server_connect_sender, mut server_connect_receiver) = channel(DEFAULT_CHANNEL_SIZE);
        let (server_disconnect_sender, mut server_disconnect_receiver) =
            channel(DEFAULT_CHANNEL_SIZE);
        let (server_receive_sender, mut server_receive_receiver) = channel(DEFAULT_CHANNEL_SIZE);
        let (server_stop_sender, mut server_stop_receiver) = channel(DEFAULT_CHANNEL_SIZE);
        let (client_receive_sender, mut client_receive_receiver) = channel(DEFAULT_CHANNEL_SIZE);
        let (client_disconnect_sender, mut client_disconnect_receiver) =
            channel(DEFAULT_CHANNEL_SIZE);

        let server_handler = ServerHandler::new(
            server_connect_sender,
            server_disconnect_sender,
            server_receive_sender,
            server_stop_sender,
        );
        let client_handler = ClientHandler::new(client_receive_sender, client_disconnect_sender);

        let mut server = Server::builder()
            .sending::<usize>()
            .receiving::<String>()
            .with_event_handler(server_handler)
            .start(SERVER_ADDR)
            .await
            .unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let mut client = Client::builder()
            .sending::<String>()
            .receiving::<usize>()
            .with_event_handler(client_handler)
            .connect(server_addr)
            .await
            .unwrap();
        sleep!();

        let client_addr = client.get_addr().await.unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_connect_receiver.recv().await.unwrap();
        assert_eq!(client_connect_event, 0);
        sleep!();

        let msg_from_server = 29275;
        server.send_all(msg_from_server).await.unwrap();
        sleep!();

        let client_recv_event_1 = client_receive_receiver.recv().await.unwrap();
        assert_eq!(client_recv_event_1, msg_from_server);
        sleep!();

        let msg_from_client = "Hello, server!".to_owned();
        client.send(msg_from_client.clone()).await.unwrap();
        sleep!();

        let server_recv_event = server_receive_receiver.recv().await.unwrap();
        assert_eq!(server_recv_event, (0, msg_from_client.clone()));
        server
            .send(server_recv_event.0, server_recv_event.1.len())
            .await
            .unwrap();
        sleep!();

        let client_recv_event_2 = client_receive_receiver.recv().await.unwrap();
        assert_eq!(client_recv_event_2, msg_from_client.len());
        sleep!();

        client.disconnect().await.unwrap();
        client_disconnect_receiver.recv().await.unwrap();
        sleep!();

        let client_disconnect_event = server_disconnect_receiver.recv().await.unwrap();
        assert_eq!(client_disconnect_event, 0);
        sleep!();

        server.stop().await.unwrap();
        server_stop_receiver.recv().await.unwrap();
        sleep!();

        assert!(server_connect_receiver.try_recv().is_err());
        assert!(server_disconnect_receiver.try_recv().is_err());
        assert!(server_receive_receiver.try_recv().is_err());
        assert!(server_stop_receiver.try_recv().is_err());
        assert!(client_receive_receiver.try_recv().is_err());
        assert!(client_disconnect_receiver.try_recv().is_err());
        sleep!();
    }

    /// Test builder with channel configuration.
    #[tokio::test]
    async fn test_builder_with_channel_config() {
        let (mut server, mut server_events) = Server::builder()
            .sending::<usize>()
            .receiving::<String>()
            .with_event_channel()
            .start(SERVER_ADDR)
            .await
            .unwrap();
        sleep!();

        let server_addr = server.get_addr().await.unwrap();
        println!("Server address: {}", server_addr);
        sleep!();

        let (mut client, mut client_events) = Client::builder()
            .sending::<String>()
            .receiving::<usize>()
            .with_event_channel()
            .connect(server_addr)
            .await
            .unwrap();
        sleep!();

        let client_addr = client.get_addr().await.unwrap();
        println!("Client address: {}", client_addr);
        sleep!();

        let client_connect_event = server_events.next().await.unwrap();
        assert!(matches!(
            client_connect_event,
            ServerEvent::Connect { client_id: 0 }
        ));
        sleep!();

        let msg_from_server = 29275;
        server.send_all(msg_from_server).await.unwrap();
        sleep!();

        let client_recv_event_1 = client_events.next().await.unwrap();
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

        let server_recv_event = server_events.next().await.unwrap();
        match server_recv_event {
            ServerEvent::Receive { client_id, data } => {
                assert_eq!(client_id, 0);
                assert_eq!(data, msg_from_client);
                server.send(client_id, data.len()).await.unwrap();
            }
            event => panic!("expected receive event on server, instead got {:?}", event),
        }
        sleep!();

        let client_recv_event_2 = client_events.next().await.unwrap();
        match client_recv_event_2 {
            ClientEvent::Receive { data } => {
                assert_eq!(data, msg_from_client.len());
            }
            event => panic!("expected receive event on client, instead got {:?}", event),
        }
        sleep!();

        client.disconnect().await.unwrap();
        let disconnect_event = client_events.next().await.unwrap();
        assert!(matches!(disconnect_event, ClientEvent::Disconnect));
        sleep!();

        let client_disconnect_event = server_events.next().await.unwrap();
        assert!(matches!(
            client_disconnect_event,
            ServerEvent::Disconnect { client_id: 0 }
        ));
        sleep!();

        server.stop().await.unwrap();
        let stop_event = server_events.next().await.unwrap();
        assert!(matches!(stop_event, ServerEvent::Stop));
        sleep!();

        assert!(client_events.next().await.is_none());
        assert!(server_events.next().await.is_none());
        sleep!();
    }
}
