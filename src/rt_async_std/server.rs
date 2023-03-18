use super::command_channel::*;
use super::event_stream::*;
use super::timeout::*;
use crate::crypto::*;
use crate::util::*;
use async_std::channel::{bounded, Sender};
use async_std::net::{TcpListener, TcpStream, ToSocketAddrs};
use async_std::task::JoinHandle;
use futures::future::FutureExt;
use futures::{AsyncReadExt, AsyncWriteExt};
use rsa::pkcs8::EncodePublicKey;
use serde::{de::DeserializeOwned, ser::Serialize};
use std::collections::HashMap;
use std::io;
use std::marker::PhantomData;
use std::net::{Shutdown, SocketAddr};

/// A command sent from the server handle to the background server task.
pub enum ServerCommand<S>
where
    S: Serialize + Clone + Send + 'static,
{
    /// Stop the server.
    Stop,
    /// Send data to a client.
    Send { client_id: usize, data: S },
    /// Send data to all clients.
    SendAll { data: S },
    /// Get the local server address.
    GetAddr,
    /// Get the address of a client.
    GetClientAddr { client_id: usize },
    /// Disconnect a client from the server.
    RemoveClient { client_id: usize },
}

/// The return value of a command executed on the background server task.
pub enum ServerCommandReturn {
    /// Stop return value.
    Stop(io::Result<()>),
    /// Sent data return value.
    Send(io::Result<()>),
    /// Sent data to all return value.
    SendAll(io::Result<()>),
    /// Local server address return value.
    GetAddr(io::Result<SocketAddr>),
    /// Client address return value.
    GetClientAddr(io::Result<SocketAddr>),
    /// Disconnect client return value.
    RemoveClient(io::Result<()>),
}

/// A command sent from the server background task to a client background task.
pub enum ServerClientCommand<S>
where
    S: Serialize + Clone + Send + 'static,
{
    /// Send data to the client.
    Send { data: S },
    /// Get the address of the client.
    GetAddr,
    /// Disconnect the client.
    Remove,
}

/// The return value of a command executed on a client background task.
pub enum ServerClientCommandReturn {
    /// Send data return value.
    Send(io::Result<()>),
    /// Client address return value.
    GetAddr(io::Result<SocketAddr>),
    /// Disconnect client return value.
    Remove(io::Result<()>),
}

/// An event from the server.
///
/// ```no_run
/// use rustdtp::rt_async_std::*;
///
/// #[async_std::main]
/// async fn main() {
///     // Create the server
///     let (mut server, mut server_event) = Server::<(), String>::start(("0.0.0.0", 0)).await.unwrap();
///
///     // Iterate over events
///     while let Some(event) = server_event.next().await {
///         match event {
///             ServerEvent::Connect { client_id } => {
///                 println!("Client with ID {} connected", client_id);
///             }
///             ServerEvent::Disconnect { client_id } => {
///                 println!("Client with ID {} disconnected", client_id);
///             }
///             ServerEvent::Receive { client_id, data } => {
///                 println!("Client with ID {} sent: {}", client_id, data);
///             }
///             ServerEvent::Stop => {
///                 // No more events will be sent, and the loop will end
///                 println!("Server closed");
///             }
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub enum ServerEvent<R>
where
    R: DeserializeOwned + Send + 'static,
{
    /// A client connected.
    Connect { client_id: usize },
    /// A client disconnected.
    Disconnect { client_id: usize },
    /// Data received from a client.
    Receive { client_id: usize, data: R },
    /// Server stopped.
    Stop,
}

/// A handle to the server.
pub struct ServerHandle<S>
where
    S: Serialize + Clone + Send + 'static,
{
    /// The channel through which commands can be sent to the background task.
    server_command_sender: CommandChannelSender<ServerCommand<S>, ServerCommandReturn>,
    /// The handle to the background task.
    server_task_handle: JoinHandle<io::Result<()>>,
}

impl<S> ServerHandle<S>
where
    S: Serialize + Clone + Send + 'static,
{
    /// Stop the server, disconnect all clients, and shut down all network interfaces.
    ///
    /// Returns a result of the error variant if an error occurred while disconnecting clients.
    ///
    /// ```no_run
    /// use rustdtp::rt_async_std::*;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     // Create the server
    ///     let (mut server, mut server_event) = Server::<(), String>::start(("0.0.0.0", 0)).await.unwrap();
    ///
    ///     // Wait for events until a client requests the server be stopped
    ///     while let Some(event) = server_event.next().await {
    ///         match event {
    ///             // Stop the server when a client requests it be stopped
    ///             ServerEvent::Receive { client_id, data } => {
    ///                 if data.as_str() == "Stop the server!" {
    ///                     println!("Server stop requested");
    ///                     server.stop().await.unwrap();
    ///                     break;
    ///                 }
    ///             }
    ///             _ => {}  // Do nothing for other events
    ///         }
    ///     }
    ///
    ///     // The last event should be a stop event
    ///     assert!(matches!(server_event.next().await.unwrap(), ServerEvent::Stop));
    /// }
    /// ```
    pub async fn stop(self) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::Stop)
            .await?;
        self.server_task_handle.await?;
        unwrap_enum!(value, ServerCommandReturn::Stop)
    }

    /// Send data to a client.
    ///
    /// `client_id`: the ID of the client to send the data to.
    /// `data`: the data to send.
    ///
    /// Returns a result of the error variant if an error occurred while sending.
    ///
    /// ```no_run
    /// use rustdtp::rt_async_std::*;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     // Create the server
    ///     let (mut server, mut server_event) = Server::<String, ()>::start(("0.0.0.0", 0)).await.unwrap();
    ///
    ///     // Iterate over events
    ///     while let Some(event) = server_event.next().await {
    ///         match event {
    ///             // When a client connects, send a greeting
    ///             ServerEvent::Connect { client_id } => {
    ///                 server.send(client_id, format!("Hello, client {}!", client_id)).await.unwrap();
    ///             }
    ///             _ => {}  // Do nothing for other events
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn send(&mut self, client_id: usize, data: S) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::Send { client_id, data })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::Send)
    }

    /// Send data to all clients.
    ///
    /// `data`: the data to send.
    ///
    /// Returns a result of the error variant if an error occurred while sending.
    ///
    /// ```no_run
    /// use rustdtp::rt_async_std::*;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     // Create the server
    ///     let (mut server, mut server_event) = Server::<String, ()>::start(("0.0.0.0", 0)).await.unwrap();
    ///
    ///     // Iterate over events
    ///     while let Some(event) = server_event.next().await {
    ///         match event {
    ///             // When a client connects, notify all clients
    ///             ServerEvent::Connect { client_id } => {
    ///                 server.send_all(format!("A new client with ID {} has joined!", client_id)).await.unwrap();
    ///             }
    ///             _ => {}  // Do nothing for other events
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn send_all(&mut self, data: S) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::SendAll { data })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::SendAll)
    }

    /// Get the address the server is listening on.
    ///
    /// Returns a result containing the address the server is listening on, or the error variant if an error occurred.
    ///
    /// ```no_run
    /// use rustdtp::rt_async_std::*;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     // Create the server
    ///     let (mut server, mut server_event) = Server::<(), ()>::start(("0.0.0.0", 0)).await.unwrap();
    ///
    ///     // Get the server address
    ///     let addr = server.get_addr().await.unwrap();
    ///     println!("Server listening on {}", addr);
    /// }
    /// ```
    pub async fn get_addr(&mut self) -> io::Result<SocketAddr> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::GetAddr)
            .await?;
        unwrap_enum!(value, ServerCommandReturn::GetAddr)
    }

    /// Get the address of a connected client.
    ///
    /// `client_id`: the ID of the client.
    ///
    /// Returns a result containing the address of the client, or the error variant if the client ID is invalid.
    ///
    /// ```no_run
    /// use rustdtp::rt_async_std::*;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     // Create the server
    ///     let (mut server, mut server_event) = Server::<(), ()>::start(("0.0.0.0", 0)).await.unwrap();
    ///
    ///     // Iterate over events
    ///     while let Some(event) = server_event.next().await {
    ///         match event {
    ///             // When a client connects, get their address
    ///             ServerEvent::Connect { client_id } => {
    ///                 let addr = server.get_client_addr(client_id).await.unwrap();
    ///                 println!("Client with ID {} connected from {}", client_id, addr);
    ///             }
    ///             _ => {}  // Do nothing for other events
    ///         }
    ///     }
    /// }
    pub async fn get_client_addr(&mut self, client_id: usize) -> io::Result<SocketAddr> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::GetClientAddr { client_id })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::GetClientAddr)
    }

    /// Disconnect a client from the server.
    ///
    /// `client_id`: the ID of the client.
    ///
    /// Returns a result of the error variant if an error occurred while disconnecting the client, or if the client ID is invalid.
    ///
    /// ```no_run
    /// use rustdtp::rt_async_std::*;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     // Create the server
    ///     let (mut server, mut server_event) = Server::<String, i32>::start(("0.0.0.0", 0)).await.unwrap();
    ///
    ///     // Iterate over events
    ///     while let Some(event) = server_event.next().await {
    ///         match event {
    ///             // Disconnect a client if they send an even number
    ///             ServerEvent::Receive { client_id, data } => {
    ///                 if data % 2 == 0 {
    ///                     println!("Disconnecting client with ID {}", client_id);
    ///                     server.send(client_id, "Even numbers are not allowed".to_owned()).await.unwrap();
    ///                     server.remove_client(client_id).await.unwrap();
    ///                 }
    ///             }
    ///             _ => {}  // Do nothing for other events
    ///         }
    ///     }
    ///
    ///     // The last event should be a stop event
    ///     assert!(matches!(server_event.next().await.unwrap(), ServerEvent::Stop));
    /// }
    /// ```
    pub async fn remove_client(&mut self, client_id: usize) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::RemoveClient { client_id })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::RemoveClient)
    }
}

/// A socket server.
///
/// The server takes two generic parameters:
///
/// - `S`: the type of data that will be **sent** to clients.
/// - `R`: the type of data that will be **received** from clients.
///
/// Both types must be serializable in order to be sent through the socket. When creating clients, the types should be swapped, since the server's send type will be the client's receive type and vice versa.
///
/// ```no_run
/// use rustdtp::rt_async_std::*;
///
/// #[async_std::main]
/// async fn main() {
///     // Create a server that receives strings and returns the length of each string
///     let (mut server, mut server_event) = Server::<usize, String>::start(("0.0.0.0", 0)).await.unwrap();
///
///     // Iterate over events
///     while let Some(event) = server_event.next().await {
///         match event {
///             ServerEvent::Connect { client_id } => {
///                 println!("Client with ID {} connected", client_id);
///             }
///             ServerEvent::Disconnect { client_id } => {
///                 println!("Client with ID {} disconnected", client_id);
///             }
///             ServerEvent::Receive { client_id, data } => {
///                 // Send back the length of the string
///                 server.send(client_id, data.len()).await.unwrap();
///             }
///             ServerEvent::Stop => {
///                 // No more events will be sent, and the loop will end
///                 println!("Server closed");
///             }
///         }
///     }
/// }
/// ```
pub struct Server<S, R>
where
    S: Serialize + Clone + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    /// Phantom value for `S`.
    phantom_send: PhantomData<S>,
    /// Phantom value for `R`.
    phantom_receive: PhantomData<R>,
}

impl<S, R> Server<S, R>
where
    S: Serialize + Clone + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    /// Start a socket server.
    ///
    /// `addr`: the address for the server to listen on.
    ///
    /// Returns a result containing a handle to the server and a channel from which to receive server events, or the error variant if an error occurred while starting the server.
    ///
    /// ```no_run
    /// use rustdtp::rt_async_std::*;
    ///
    /// #[async_std::main]
    /// async fn main() {
    ///     let (mut server, mut server_event) = Server::<(), ()>::start(("0.0.0.0", 0)).await.unwrap();
    /// }
    /// ```
    ///
    /// Neither the server handle nor the event receiver should be dropped until the server has been stopped. Prematurely dropping either one can cause unintended behavior.
    pub async fn start<A>(addr: A) -> io::Result<(ServerHandle<S>, EventStream<ServerEvent<R>>)>
    where
        A: ToSocketAddrs,
    {
        // Server TCP listener
        let listener = TcpListener::bind(addr).await?;
        // Channels for sending commands from the server handle to the background server task
        let (server_command_sender, server_command_receiver) = command_channel();
        // Channels for sending event notifications from the background server task
        let (server_event_sender, server_event_receiver) = bounded(CHANNEL_BUFFER_SIZE);

        // Start the background server task, saving the join handle for when the server is stopped
        let server_task_handle = async_std::task::spawn(server_handler(
            listener,
            server_event_sender,
            server_command_receiver,
        ));

        // Create a handle for the server
        let server_handle = ServerHandle {
            server_command_sender,
            server_task_handle,
        };

        // Create an event stream for the server
        let server_event_stream = EventStream::new(server_event_receiver);

        Ok((server_handle, server_event_stream))
    }
}

/// The server client loop. Handles received data and commands.
async fn server_client_loop<S, R>(
    client_id: usize,
    mut socket: TcpStream,
    aes_key: [u8; AES_KEY_SIZE],
    server_client_event_sender: Sender<ServerEvent<R>>,
    client_command_receiver: CommandChannelReceiver<
        ServerClientCommand<S>,
        ServerClientCommandReturn,
    >,
) -> io::Result<()>
where
    S: Serialize + Clone + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    // Buffer in which to receive the size portion of a message
    let mut size_buffer = [0; LEN_SIZE];

    // Client loop
    loop {
        // Await messages from the client
        // and commands from the background server task
        futures::select! {
            // Read the size portion from the client socket
            read_value = socket.read(&mut size_buffer).fuse() => {
                // Return an error if the socket could not be read
                let n_size = read_value?;

                // If there were no bytes read, or if there were fewer bytes read than there
                // should have been, close the socket
                if n_size != LEN_SIZE {
                    socket.shutdown(Shutdown::Both)?;
                    break;
                };

                // Decode the size portion of the message
                let encrypted_data_size = decode_message_size(&size_buffer);
                // Initialize the buffer for the data portion of the message
                let mut encrypted_data_buffer = vec![0; encrypted_data_size];

                // Read the data portion from the client socket, returning an error if the
                // socket could not be read
                let n_data = data_read_timeout! {
                    socket.read(&mut encrypted_data_buffer)
                }??;

                // If there were no bytes read, or if there were fewer bytes read than there
                // should have been, close the socket
                if n_data != encrypted_data_size {
                    socket.shutdown(Shutdown::Both)?;
                    break;
                }

                // Decrypt the data
                let data_buffer = match aes_decrypt(&aes_key, &encrypted_data_buffer) {
                    Ok(val) => Ok(val),
                    Err(e) => generic_io_error(format!("failed to decrypt data: {}", e)),
                }?;

                // Deserialize the message data
                if let Ok(data) = serde_json::from_slice(&data_buffer) {
                    // Send an event to note that a piece of data has been received from
                    // a client
                    if let Err(_e) = server_client_event_sender.send(ServerEvent::Receive { client_id, data }).await {
                        // Sending failed, disconnect the client
                        socket.shutdown(Shutdown::Both)?;
                        break;
                    }
                } else {
                    // Deserialization failed, disconnect the client
                    socket.shutdown(Shutdown::Both)?;
                    break;
                }
            }
            // Process a command sent to the client
            client_command_value = client_command_receiver.recv_command().fuse() => {
                // Handle the command, or lack thereof if the channel is closed
                match client_command_value {
                    Ok(client_command) => {
                        // Process the command
                        match client_command {
                            ServerClientCommand::Send { data } => {
                                let value = 'val: {
                                    // Serialize the data
                                    let data_buffer = break_on_err!(into_generic_io_result(serde_json::to_vec(&data)), 'val);
                                    // Encrypt the serialized data
                                    let encrypted_data_buffer = break_on_err!(into_generic_io_result(aes_encrypt(&aes_key, &data_buffer)), 'val);
                                    // Encode the message size to a buffer
                                    let size_buffer = encode_message_size(encrypted_data_buffer.len());

                                    // Initialize the message buffer
                                    let mut buffer = vec![];
                                    // Extend the buffer to contain the payload size
                                    buffer.extend_from_slice(&size_buffer);
                                    // Extend the buffer to contain the payload data
                                    buffer.extend(&encrypted_data_buffer);

                                    // Write the data to the client socket
                                    let n = break_on_err!(socket.write(&buffer).await, 'val);
                                    // Flush the stream
                                    break_on_err!(socket.flush().await, 'val);

                                    // If there were no bytes written, or if there were fewer
                                    // bytes written than there should have been, close the
                                    // socket
                                    if n != buffer.len() {
                                        generic_io_error("failed to write data to socket")
                                    } else {
                                        Ok(())
                                    }
                                };

                                let error_occurred = value.is_err();

                                // Return the status of the send operation
                                if let Err(_e) = client_command_receiver.command_return(ServerClientCommandReturn::Send(value)).await {
                                    // Channel is closed, disconnect the client
                                    socket.shutdown(Shutdown::Both)?;
                                    break;
                                }

                                // If the send failed, disconnect the client
                                if error_occurred {
                                    socket.shutdown(Shutdown::Both)?;
                                    break;
                                }
                            },
                            ServerClientCommand::GetAddr => {
                                // Get the client socket's address
                                let addr = socket.peer_addr();

                                // Return the address
                                if let Err(_e) = client_command_receiver.command_return(ServerClientCommandReturn::GetAddr(addr)).await {
                                    // Channel is closed, disconnect the client
                                    socket.shutdown(Shutdown::Both)?;
                                    break;
                                }
                            },
                            ServerClientCommand::Remove => {
                                // Disconnect the client
                                let value = socket.shutdown(Shutdown::Both);

                                // Return the status of the remove operation, ignoring
                                // failures, since a failure indicates that the client has
                                // probably already disconnected
                                if let Err(_e) = client_command_receiver.command_return(ServerClientCommandReturn::Remove(value)).await {}

                                // Break the client loop
                                break;
                            },
                        }
                    },
                    Err(_e) => {
                        // Channel is closed, disconnect the client
                        socket.shutdown(Shutdown::Both)?;
                        break;
                    },
                }
            }
        }
    }

    Ok(())
}

/// Starts a server client loop in the background.
async fn server_client_handler<S, R>(
    client_id: usize,
    mut socket: TcpStream,
    server_client_event_sender: Sender<ServerEvent<R>>,
    client_cleanup_sender: Sender<usize>,
) -> io::Result<(
    CommandChannelSender<ServerClientCommand<S>, ServerClientCommandReturn>,
    JoinHandle<io::Result<()>>,
)>
where
    S: Serialize + Clone + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    // Generate RSA keys
    let (rsa_pub, rsa_priv) = into_generic_io_result(rsa_keys())?;
    // Convert the RSA public key into a string...
    let rsa_pub_str =
        into_generic_io_result(rsa_pub.to_public_key_pem(rsa::pkcs1::LineEnding::LF))?;
    // ...and then into bytes
    let rsa_pub_bytes = rsa_pub_str.as_bytes();
    // Create the buffer containing the RSA public key and its size
    let mut rsa_pub_buffer = encode_message_size(rsa_pub_bytes.len()).to_vec();
    // Extend the buffer with the RSA public key bytes
    rsa_pub_buffer.extend(rsa_pub_bytes);
    // Send the RSA public key to the client
    let n = socket.write(&rsa_pub_buffer).await?;
    // Flush the stream
    socket.flush().await?;

    // If there were no bytes written, or if there were fewer
    // bytes written than there should have been, close the
    // socket and exit
    if n != rsa_pub_buffer.len() {
        socket.shutdown(Shutdown::Both)?;
        return generic_io_error("failed to write RSA public key data to socket");
    }

    // Buffer in which to receive the size portion of the AES key
    let mut aes_key_size_buffer = [0; LEN_SIZE];
    // Read the AES key from the client
    let n_size = handshake_timeout! {
        socket.read(&mut aes_key_size_buffer)
    }??;

    // If there were no bytes read, or if there were fewer bytes read than there
    // should have been, close the socket and exit
    if n_size != LEN_SIZE {
        socket.shutdown(Shutdown::Both)?;
        return generic_io_error("failed to read AES key size from socket");
    };

    // Decode the size portion of the AES key
    let aes_key_size = decode_message_size(&aes_key_size_buffer);
    // Initialize the buffer for the AES key
    let mut aes_key_buffer = vec![0; aes_key_size];

    // Read the AES key portion from the client socket, returning an error if the
    // socket could not be read
    let n_aes_key = data_read_timeout! {
        socket.read(&mut aes_key_buffer)
    }??;

    // If there were no bytes read, or if there were fewer bytes read than there
    // should have been, close the socket and exit
    if n_aes_key != aes_key_size {
        socket.shutdown(Shutdown::Both)?;
        return generic_io_error("failed to read AES key data from socket");
    }

    // Decrypt the AES key
    let aes_key_decrypted = into_generic_io_result(rsa_decrypt(&rsa_priv, &aes_key_buffer))?;

    // Assert that the AES key is the correct size
    let aes_key: [u8; AES_KEY_SIZE] = match aes_key_decrypted.try_into() {
        Ok(val) => Ok(val),
        Err(_e) => generic_io_error("unexpected size for AES key"),
    }?;

    // Channels for sending commands from the background server task to a background client task
    let (client_command_sender, client_command_receiver) = command_channel();

    // Start a background client task, saving the join handle for when the server is stopped
    let client_task_handle = async_std::task::spawn(async move {
        let res = server_client_loop(
            client_id,
            socket,
            aes_key,
            server_client_event_sender,
            client_command_receiver,
        )
        .await;

        // Tell the server to clean up after the client, ignoring failures, since a failure
        // indicates that the server has probably closed
        if let Err(_e) = client_cleanup_sender.send(client_id).await {}

        res
    });

    Ok((client_command_sender, client_task_handle))
}

/// The server loop. Handles incoming connections and commands.
async fn server_loop<S, R>(
    listener: TcpListener,
    server_event_sender: Sender<ServerEvent<R>>,
    server_command_receiver: CommandChannelReceiver<ServerCommand<S>, ServerCommandReturn>,
    client_command_senders: &mut HashMap<
        usize,
        CommandChannelSender<ServerClientCommand<S>, ServerClientCommandReturn>,
    >,
    client_join_handles: &mut HashMap<usize, JoinHandle<io::Result<()>>>,
) -> io::Result<()>
where
    S: Serialize + Clone + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    // ID assigned to the next client
    let mut next_client_id = 0usize;
    // Channel for indicating that a client needs to be cleaned up after
    let (server_client_cleanup_sender, server_client_cleanup_receiver) =
        bounded::<usize>(CHANNEL_BUFFER_SIZE);

    // Server loop
    loop {
        // Await new clients connecting,
        // commands from the server handle,
        // and notifications of clients disconnecting
        futures::select! {
            // Accept a connecting client
            accept_value = listener.accept().fuse() => {
                // Get the client socket, exiting if an error occurs
                let (socket, _) = accept_value?;
                // New client ID
                let client_id = next_client_id.clone();
                // Increment next client ID
                next_client_id += 1;
                // Clone the event sender so the background client tasks can send events
                let server_client_event_sender = server_event_sender.clone();
                // Clone the client cleanup sender to the background client tasks can be cleaned up properly
                let client_cleanup_sender = server_client_cleanup_sender.clone();

                // Handle the new connection
                match server_client_handler(client_id, socket, server_client_event_sender, client_cleanup_sender).await {
                    Ok((client_command_sender, client_task_handle)) => {
                        // Keep track of client command senders
                        client_command_senders.insert(client_id, client_command_sender);
                        // Keep track of client task handles
                        client_join_handles.insert(client_id, client_task_handle);

                        // Send an event to note that a client has connected successfully
                        if let Err(_e) = server_event_sender
                            .send(ServerEvent::Connect { client_id })
                            .await
                        {
                            // Server is probably closed
                            break;
                        }
                    },
                    Err(e) => {
                        if cfg!(test) {
                            // If testing, fail
                            Err(e)?
                        } else {
                            // If not testing, ignore client handshake errors
                        }
                    }
                }
            },
            // Process a command from the server handle
            command_value = server_command_receiver.recv_command().fuse() => {
                // Handle the command, or lack thereof if the channel is closed
                match command_value {
                    Ok(command) => {
                        match command {
                            ServerCommand::Stop => {
                                // If a command fails to send, the server has already closed,
                                // and the error can be ignored.
                                // It should be noted that this is not where the stop method actually returns
                                // its `Result`. This immediately returns with an `Ok` status. The real return
                                // value is the `Result` returned from the server task join handle.
                                if let Ok(_) = server_command_receiver.command_return(ServerCommandReturn::Stop(Ok(()))).await {}

                                // Break the server loop, the clients will be disconnected before the task ends
                                break;
                            },
                            ServerCommand::Send { client_id, data } => {
                                let value = match client_command_senders.get_mut(&client_id) {
                                    Some(client_command_sender) => match client_command_sender.send_command(ServerClientCommand::Send { data }).await {
                                        Ok(return_value) => unwrap_enum!(return_value, ServerClientCommandReturn::Send),
                                        Err(_e) => {
                                            // The channel is closed, and the client has probably been
                                            // disconnected, so the error can be ignored
                                            Ok(())
                                        },
                                    },
                                    None => generic_io_error("invalid client"),
                                };

                                // If a command fails to send, the client has probably disconnected,
                                // and the error can be ignored
                                if let Ok(_) = server_command_receiver.command_return(ServerCommandReturn::Send(value)).await {}
                            },
                            ServerCommand::SendAll { data } => {
                                for (_client_id, client_command_sender) in client_command_senders.iter_mut() {
                                    let data_clone = data.clone();

                                    match client_command_sender.send_command(ServerClientCommand::Send { data: data_clone }).await {
                                        Ok(return_value) => unwrap_enum!(return_value, ServerClientCommandReturn::Send),
                                        Err(_e) => {
                                            // The channel is closed, and the client has probably been
                                            // disconnected, so the error can be ignored
                                            Ok(())
                                        },
                                    }.unwrap();
                                };

                                // If a command fails to send, the client has probably disconnected,
                                // and the error can be ignored
                                if let Ok(_) = server_command_receiver.command_return(ServerCommandReturn::SendAll(Ok(()))).await {}
                            },
                            ServerCommand::GetAddr => {
                                // Get the server listener's address
                                let addr = listener.local_addr();

                                // If a command fails to send, the client has probably disconnected,
                                // and the error can be ignored
                                if let Ok(_) = server_command_receiver.command_return(ServerCommandReturn::GetAddr(addr)).await {}
                            },
                            ServerCommand::GetClientAddr { client_id } => {
                                let value = match client_command_senders.get_mut(&client_id) {
                                    Some(client_command_sender) => match client_command_sender.send_command(ServerClientCommand::GetAddr).await {
                                        Ok(return_value) => unwrap_enum!(return_value, ServerClientCommandReturn::GetAddr),
                                        Err(_e) => {
                                            // The channel is closed, and the client has probably been
                                            // disconnected, so the error can be treated as an invalid
                                            // client error
                                            generic_io_error("invalid client")
                                        },
                                    },
                                    None => generic_io_error("invalid client"),
                                };

                                // If a command fails to send, the client has probably disconnected,
                                // and the error can be ignored
                                if let Ok(_) = server_command_receiver.command_return(ServerCommandReturn::GetClientAddr(value)).await {}
                            },
                            ServerCommand::RemoveClient { client_id } => {
                                let value = match client_command_senders.get_mut(&client_id) {
                                    Some(client_command_sender) => match client_command_sender.send_command(ServerClientCommand::Remove).await {
                                        Ok(return_value) => unwrap_enum!(return_value, ServerClientCommandReturn::Remove),
                                        Err(_e) => {
                                            // The channel is closed, and the client has probably been
                                            // disconnected, so the error can be ignored
                                            Ok(())
                                        },
                                    },
                                    None => generic_io_error("invalid client"),
                                };

                                // If a command fails to send, the client has probably disconnected already,
                                // and the error can be ignored
                                if let Ok(_) = server_command_receiver.command_return(ServerCommandReturn::RemoveClient(value)).await {}
                            },
                        }
                    },
                    Err(_e) => {
                        // Server is probably closed, exit
                        break;
                    },
                }
            }
            // Clean up after a disconnecting client
            disconnecting_client_id = server_client_cleanup_receiver.recv().fuse() => {
                match disconnecting_client_id {
                    Ok(client_id) => {
                        // Remove the client's command sender, which will be dropped after this block ends
                        client_command_senders.remove(&client_id);

                        // Remove the client's join handle
                        if let Some(handle) = client_join_handles.remove(&client_id) {
                            // Join the client's handle
                            if let Err(e) = handle.await {
                                if cfg!(test) {
                                    // If testing, fail
                                    Err(e)?
                                } else {
                                    // If not testing, ignore client handler errors
                                }
                            }
                        }

                        // Send an event to note that a client has disconnected
                        if let Err(_e) = server_event_sender.send(ServerEvent::Disconnect { client_id }).await {
                            // Server is probably closed, exit
                            break;
                        }
                    },
                    Err(_e) => {
                        // Server is probably closed, exit
                        break;
                    },
                }
            }
        }
    }

    Ok(())
}

/// Starts the server loop task in the background.
async fn server_handler<S, R>(
    listener: TcpListener,
    server_event_sender: Sender<ServerEvent<R>>,
    server_command_receiver: CommandChannelReceiver<ServerCommand<S>, ServerCommandReturn>,
) -> io::Result<()>
where
    S: Serialize + Clone + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    // Collection of channels for sending commands from the background server task to a background client task
    let mut client_command_senders: HashMap<
        usize,
        CommandChannelSender<ServerClientCommand<S>, ServerClientCommandReturn>,
    > = HashMap::new();
    // Background client task join handles
    let mut client_join_handles: HashMap<usize, JoinHandle<io::Result<()>>> = HashMap::new();

    // Wrap server loop in a block to catch all exit scenarios
    let server_exit = server_loop(
        listener,
        server_event_sender.clone(),
        server_command_receiver,
        &mut client_command_senders,
        &mut client_join_handles,
    )
    .await;

    // Send a remove command to all clients
    for (_client_id, client_command_sender) in client_command_senders {
        // If a command fails to send, the client has probably disconnected already,
        // and the error can be ignored
        if let Ok(_) = client_command_sender
            .send_command(ServerClientCommand::Remove)
            .await
        {}
    }

    // Join all background client tasks before exiting
    for (_client_id, handle) in client_join_handles {
        if let Err(e) = handle.await {
            if cfg!(test) {
                // If testing, fail
                Err(e)?
            } else {
                // If not testing, ignore client handler errors
            }
        }
    }

    // Send a stop event, ignoring send errors
    if let Err(_e) = server_event_sender.send(ServerEvent::Stop).await {}

    // Return server loop result
    server_exit
}
