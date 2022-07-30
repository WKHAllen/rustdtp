# Rust Data Transfer Protocol

Asynchronous cross-platform networking interfaces for Rust.

The two fundamental network objects this crate provides are the server and client. When starting a server or connecting via a client, the task will not block while it performs network operations in the background. Upon instantiation, both the server and client return handles that provide a mechanism for communicating with the background task, and instructing it to provide status information or halt network operations.

## Creating a server

A server can be built using the `Server` implementation:

```rust
use rustdtp::{Server, ServerEvent};

#[tokio::main]
async fn main() {
    // Create a server that receives strings and returns the length of each string
    let (mut server, mut server_event) = Server::<usize, String>::start(("0.0.0.0", 0)).await.unwrap();

    // Iterate over events
    while let Some(event) = server_event.next().await {
        match event {
            ServerEvent::Connect { client_id } => {
                println!("Client with ID {} connected", client_id);
            },
            ServerEvent::Disconnect { client_id } => {
                println!("Client with ID {} disconnected", client_id);
            },
            ServerEvent::Receive { client_id, data } => {
                // Send back the length of the string
                server.send(client_id, data.len()).await.unwrap();
            },
            ServerEvent::Stop => {
                // No more events will be sent, and the loop will end
                println!("Server closed");
            },
        }
    }
}
```

## Creating a client

A client can be built using the `Client` implementation:

```rust
use rustdtp::{Client, ClientEvent};

#[tokio::main]
async fn main() {
    // Create a client that sends a message to the server and receives the length of the message
    let (mut client, mut client_event) = Client::<String, usize>::connect(("127.0.0.1", 29275)).await.unwrap();

    // Send a message to the server
    let msg = "Hello, server!".to_owned();
    client.send(msg.clone()).await.unwrap();

    // Receive the response
    match client_event.next().await.unwrap() {
        ClientEvent::Receive { data } => {
            // Validate the response
            println!("Received response from server: {}", data);
            assert_eq!(data, msg.len());
        },
        event => {
            // Unexpected response
            panic!("expected to receive a response from the server, instead got {:?}", event);
        },
    }
}
```

## Event iteration

Note that in order to iterate over events, the `EventStreamExt` extension trait needs to be in scope.

## Security

Information security comes included. Every message sent over a network interface is encrypted with AES-256. Key exchanges are performed using a 2048-bit RSA key-pair.
