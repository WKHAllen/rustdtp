# Rust Data Transfer Protocol

Cross-platform networking interfaces for Rust.

The two fundamental network objects this library provides are the server and client. When starting a server or connecting via a client, the thread will not block while it performs network operations in the background. Upon instantiation, both the server and client return handles that provide a mechanism for communicating with the background thread, and instructing it to provide status information or halt network operations. If any network object goes out of scope before background operations are terminated, the operations will be cancelled automatically, and all network interfaces will be closed.

## Creating a server

A server can be built using the `Server` implementation:

```rust
use rustdtp::Server;

let server = Server::new()
    .on_receive(|client_id, data| {
        println!("Message from client #{}: {:?}", client_id, data);
    })
    .on_connect(|client_id| {
        println!("Client #{} connected", client_id);
    })
    .on_disconnect(|client_id| {
        println!("Client #{} disconnected", client_id);
    })
    .start("0.0.0.0", 29275)
    .unwrap();

println!("Server address: {}", server.get_addr().unwrap());
assert!(server.serving().unwrap());
server.stop().unwrap();
assert!(!server.serving().unwrap());
```

## Creating a client

A client can be built using the `Client` implementation:

```rust
use rustdtp::Client;

let client = Client::new()
    .on_receive(|data| {
        println!("Message from server: {:?}", data);
    })
    .on_disconnected(|| {
        println!("Disconnected from server");
    })
    .connect("127.0.0.1", 29275)
    .unwrap();

println!("Client address: {}", client.get_addr().unwrap());
assert!(client.connected().unwrap());
client.disconnect().unwrap();
assert!(!client.connected().unwrap());
```
