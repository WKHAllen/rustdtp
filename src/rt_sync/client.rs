use super::command_channel::*;
use super::event_iter::*;
use crate::crypto::*;
use crate::util::*;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use serde::{de::DeserializeOwned, ser::Serialize};
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{channel, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// A command sent from the client handle to the background client task.
pub enum ClientCommand<S>
where
    S: Serialize + Send + 'static,
{
    /// Disconnect from the server.
    Disconnect,
    /// Send data to the server.
    Send { data: S },
    /// Get the local client address.
    GetAddr,
    /// Get the server's address.
    GetServerAddr,
}

/// The return value of a command executed on the background client task.
pub enum ClientCommandReturn {
    /// Disconnect return value.
    Disconnect(io::Result<()>),
    /// Sent data return value.
    Send(io::Result<()>),
    /// Local client address return value.
    GetAddr(io::Result<SocketAddr>),
    /// Server address return value.
    GetServerAddr(io::Result<SocketAddr>),
}

/// An event from the client.
///
/// ```no_run
/// use rustdtp::rt_sync::*;
///
/// fn main() {
///     // Create the client
///     let (client, mut client_event) = Client::<(), String>::connect(("127.0.0.1", 29275)).unwrap();
///
///     // Iterate over events
///     while let Some(event) = client_event.next() {
///         match event {
///             ClientEvent::Receive { data } => {
///                 println!("Server sent: {}", data);
///             }
///             ClientEvent::Disconnect => {
///                 // No more events will be sent, and the loop will end
///                 println!("Client disconnected");
///             }
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub enum ClientEvent<R>
where
    R: DeserializeOwned + Send + 'static,
{
    /// Data received from the server.
    Receive { data: R },
    /// Disconnected from the server.
    Disconnect,
}

/// A handle to the client.
pub struct ClientHandle<S>
where
    S: Serialize + Send + 'static,
{
    /// The channel through which commands can be sent to the background task.
    client_command_sender: CommandChannelSender<ClientCommand<S>, ClientCommandReturn>,
    /// The handle to the background task.
    client_task_handle: JoinHandle<io::Result<()>>,
}

impl<S> ClientHandle<S>
where
    S: Serialize + Send + 'static,
{
    /// Disconnect from the server.
    ///
    /// Returns a result of the error variant if an error occurred while disconnecting.
    ///
    /// ```no_run
    /// use rustdtp::rt_sync::*;
    ///
    /// fn main() {
    ///     // Create the client
    ///     let (client, mut client_event) = Client::<(), String>::connect(("127.0.0.1", 29275)).unwrap();
    ///
    ///     // Wait for events until the server requests the client leave
    ///     while let Some(event) = client_event.next() {
    ///         match event {
    ///             ClientEvent::Receive { data } => {
    ///                 if data.as_str() == "Kindly leave" {
    ///                     println!("Client disconnect requested");
    ///                     client.disconnect().unwrap();
    ///                     break;
    ///                 }
    ///             }
    ///             _ => {}  // Do nothing for other events
    ///         }
    ///     }
    /// }
    /// ```
    pub fn disconnect(self) -> io::Result<()> {
        let value = self
            .client_command_sender
            .send_command(ClientCommand::Disconnect)?;
        self.client_task_handle.join().unwrap()?;
        unwrap_enum!(value, ClientCommandReturn::Disconnect)
    }

    /// Send data to the server.
    ///
    /// `data`: the data to send.
    ///
    /// Returns a result of the error variant if an error occurred while sending.
    ///
    /// ```no_run
    /// use rustdtp::rt_sync::*;
    ///
    /// fn main() {
    ///     // Create the client
    ///     let (client, mut client_event) = Client::<String, ()>::connect(("127.0.0.1", 29275)).unwrap();
    ///
    ///     // Send a greeting to the server upon connecting
    ///     client.send("Hello, server!".to_owned()).unwrap();
    /// }
    /// ```
    pub fn send(&self, data: S) -> io::Result<()> {
        let value = self
            .client_command_sender
            .send_command(ClientCommand::Send { data })?;
        unwrap_enum!(value, ClientCommandReturn::Send)
    }

    /// Get the address of the socket the client is connected on.
    ///
    /// Returns a result containing the address of the socket the client is connected on, or the error variant if an error occurred.
    ///
    /// ```no_run
    /// use rustdtp::rt_sync::*;
    ///
    /// fn main() {
    ///     // Create the client
    ///     let (client, mut client_event) = Client::<String, ()>::connect(("127.0.0.1", 29275)).unwrap();
    ///
    ///     // Get the client address
    ///     let addr = client.get_addr().unwrap();
    ///     println!("Client connected on {}", addr);
    /// }
    /// ```
    pub fn get_addr(&self) -> io::Result<SocketAddr> {
        let value = self
            .client_command_sender
            .send_command(ClientCommand::GetAddr)?;
        unwrap_enum!(value, ClientCommandReturn::GetAddr)
    }

    /// Get the address of the server.
    ///
    /// Returns a result containing the address of the server, or the error variant if an error occurred.
    ///
    /// ```no_run
    /// use rustdtp::rt_sync::*;
    ///
    /// fn main() {
    ///     // Create the client
    ///     let (client, mut client_event) = Client::<String, ()>::connect(("127.0.0.1", 29275)).unwrap();
    ///
    ///     // Get the server address
    ///     let addr = client.get_server_addr().unwrap();
    ///     println!("Server address: {}", addr);
    /// }
    /// ```
    pub fn get_server_addr(&self) -> io::Result<SocketAddr> {
        let value = self
            .client_command_sender
            .send_command(ClientCommand::GetServerAddr)?;
        unwrap_enum!(value, ClientCommandReturn::GetServerAddr)
    }
}

/// A socket client.
///
/// The client takes two generic parameters:
///
/// - `S`: the type of data that will be **sent** to the server.
/// - `R`: the type of data that will be **received** from the server.
///
/// Both types must be serializable in order to be sent through the socket. When creating a server, the types should be swapped, since the client's send type will be the server's receive type and vice versa.
///
/// ```no_run
/// use rustdtp::rt_sync::*;
///
/// fn main() {
///     // Create a client that sends a message to the server and receives the length of the message
///     let (client, mut client_event) = Client::<String, usize>::connect(("127.0.0.1", 29275)).unwrap();
///
///     // Send a message to the server
///     let msg = "Hello, server!".to_owned();
///     client.send(msg.clone()).unwrap();
///
///     // Receive the response
///     match client_event.next().unwrap() {
///         ClientEvent::Receive { data } => {
///             // Validate the response
///             println!("Received response from server: {}", data);
///             assert_eq!(data, msg.len());
///         }
///         event => {
///             // Unexpected response
///             panic!("expected to receive a response from the server, instead got {:?}", event);
///         }
///     }
/// }
/// ```
pub struct Client<S, R>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    /// Phantom value for `S`.
    phantom_send: PhantomData<S>,
    /// Phantom value for `R`.
    phantom_receive: PhantomData<R>,
}

impl<S, R> Client<S, R>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    /// Connect to a socket server.
    ///
    /// `addr`: the address to connect to.
    ///
    /// Returns a result containing a handle to the client and a channel from which to receive client events, or the error variant if an error occurred while connecting to the server.
    ///
    /// ```no_run
    /// use rustdtp::rt_sync::*;
    ///
    /// fn main() {
    ///     let (client, mut client_event) = Client::<(), ()>::connect(("127.0.0.1", 29275)).unwrap();
    /// }
    /// ```
    ///
    /// Neither the client handle nor the event receiver should be dropped until the client has disconnected. Prematurely dropping either one can cause unintended behavior.
    pub fn connect<A>(addr: A) -> io::Result<(ClientHandle<S>, EventIter<ClientEvent<R>>)>
    where
        A: ToSocketAddrs,
    {
        // Client TCP stream
        let mut stream = TcpStream::connect(addr)?;

        // Buffer in which to receive the size portion of the RSA public key
        let mut rsa_pub_size_buffer = [0; LEN_SIZE];

        // Set the stream to blocking mode
        stream.set_nonblocking(false)?;
        // Set the stream timeout
        stream.set_read_timeout(Some(Duration::from_millis(HANDSHAKE_TIMEOUT)))?;

        // Read size portion of RSA public key
        let n_size = stream.read(&mut rsa_pub_size_buffer)?;

        // If there were no bytes read, or if there were fewer bytes read than there
        // should have been, close the stream and exit
        if n_size != LEN_SIZE {
            stream.shutdown(Shutdown::Both)?;
            return generic_io_error("failed to read RSA public key size from stream");
        };

        // Decode the size portion of the RSA public key
        let rsa_pub_size = decode_message_size(&rsa_pub_size_buffer);
        // Initialize the buffer for the RSA public key
        let mut rsa_pub_buffer = vec![0; rsa_pub_size];

        // Set the stream timeout
        stream.set_read_timeout(Some(Duration::from_millis(DATA_READ_TIMEOUT)))?;

        // Read the RSA public key portion from the stream, returning an error if the
        // stream could not be read
        let n_rsa_pub = stream.read(&mut rsa_pub_buffer)?;

        // If there were no bytes read, or if there were fewer bytes read than there
        // should have been, close the stream and exit
        if n_rsa_pub != rsa_pub_size {
            stream.shutdown(Shutdown::Both)?;
            return generic_io_error("failed to read RSA public key data from stream");
        }

        // Read the RSA public key into a string, returning an error if UTF-8 conversion failed
        let rsa_pub_str = into_generic_io_result(String::from_utf8(rsa_pub_buffer))?;
        // Read the RSA public key string into an RSA public key object
        let rsa_pub = into_generic_io_result(RsaPublicKey::from_public_key_pem(&rsa_pub_str))?;

        // Generate AES key
        let aes_key = aes_key();
        // Encrypt AES key with RSA public key
        let aes_key_encrypted = into_generic_io_result(rsa_encrypt(&rsa_pub, &aes_key))?;
        // Create the buffer containing the AES key and its size
        let mut aes_key_buffer = encode_message_size(aes_key_encrypted.len()).to_vec();
        // Extend the buffer with the AES key
        aes_key_buffer.extend(aes_key_encrypted);
        // Send the encrypted AES key to the server
        let n = stream.write(&aes_key_buffer)?;
        // Flush the stream
        stream.flush()?;

        // If there were no bytes written, or if there were fewer
        // bytes written than there should have been, close the
        // stream and exit
        if n != aes_key_buffer.len() {
            stream.shutdown(Shutdown::Both)?;
            return generic_io_error("failed to write encrypted AES key data to stream");
        }

        // Channels for sending commands from the client handle to the background client task
        let (client_command_sender, client_command_receiver) = command_channel();
        // Channels for sending event notifications from the background client task
        let (client_event_sender, client_event_receiver) = channel();

        // Start the background client task, saving the join handle for when the client disconnects
        let client_task_handle = thread::spawn(move || {
            client_loop(
                stream,
                aes_key,
                client_event_sender,
                client_command_receiver,
            )
        });

        // Create a handle for the client
        let client_handle = ClientHandle {
            client_command_sender,
            client_task_handle,
        };

        // Create an event stream for the client
        let client_event_stream = EventIter::new(client_event_receiver);

        Ok((client_handle, client_event_stream))
    }
}

/// The client loop. Handles received data and commands.
fn client_loop<S, R>(
    mut stream: TcpStream,
    aes_key: [u8; AES_KEY_SIZE],
    client_event_sender: Sender<ClientEvent<R>>,
    client_command_receiver: CommandChannelReceiver<ClientCommand<S>, ClientCommandReturn>,
) -> io::Result<()>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    // Buffer in which to receive the size portion of a message
    let mut size_buffer = [0; LEN_SIZE];

    // Set the stream to non-blocking mode
    stream.set_nonblocking(true)?;
    // Set the stream timeout
    stream.set_read_timeout(Some(Duration::from_millis(DATA_READ_TIMEOUT)))?;

    // Client loop
    loop {
        // Await messages from the server
        // and commands from the client handle

        // Read the size portion from the stream
        match stream.read(&mut size_buffer) {
            Ok(n_size) => {
                // If there were no bytes read, or if there were fewer bytes read than there
                // should have been, close the stream
                if n_size != LEN_SIZE {
                    stream.shutdown(Shutdown::Both)?;
                    break;
                }

                // Decode the size portion of the message
                let encrypted_data_size = decode_message_size(&size_buffer);
                // Initialize the buffer for the data portion of the message
                let mut encrypted_data_buffer = vec![0; encrypted_data_size];

                // Set the stream to blocking mode
                stream.set_nonblocking(false)?;

                // Read the data portion from the client stream, returning an error if the
                // stream could not be read
                let n_data = stream.read(&mut encrypted_data_buffer)?;

                // If there were no bytes read, or if there were fewer bytes read than there
                // should have been, close the stream
                if n_data != encrypted_data_size {
                    stream.shutdown(Shutdown::Both)?;
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
                    // the server
                    if let Err(_e) = client_event_sender.send(ClientEvent::Receive { data }) {
                        // Sending failed, disconnect
                        stream.shutdown(Shutdown::Both)?;
                        break;
                    }
                } else {
                    // Deserialization failed, disconnect
                    stream.shutdown(Shutdown::Both)?;
                    break;
                }

                // Set the stream back to non-blocking mode
                stream.set_nonblocking(true)?;

                Ok(())
            }
            Err(ref e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }?;

        // Process a command from the client handle
        match client_command_receiver.try_recv_command() {
            // Handle the command, or lack thereof if the channel is closed
            Ok(client_command_value) => {
                if let Some(command) = client_command_value {
                    match command {
                        ClientCommand::Disconnect => {
                            // Disconnect from the server
                            let value = stream.shutdown(Shutdown::Both);

                            // If a command fails to send, the client has already disconnected,
                            // and the error can be ignored.
                            // It should be noted that this is not where the disconnect method actually returns
                            // its `Result`. This immediately returns with an `Ok` status. The real return
                            // value is the `Result` returned from the client task join handle.
                            if let Ok(_) = client_command_receiver
                                .command_return(ClientCommandReturn::Disconnect(value))
                            {
                            }

                            // Break the client loop
                            break;
                        }
                        ClientCommand::Send { data } => {
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

                                // Write the data to the stream
                                let n = break_on_err!(stream.write(&buffer), 'val);
                                // Flush the stream
                                break_on_err!(stream.flush(), 'val);

                                // If there were no bytes written, or if there were fewer
                                // bytes written than there should have been, close the
                                // stream
                                if n != buffer.len() {
                                    generic_io_error("failed to write data to stream")
                                } else {
                                    Ok(())
                                }
                            };

                            let error_occurred = value.is_err();

                            // Return the status of the send operation
                            if let Err(_e) = client_command_receiver
                                .command_return(ClientCommandReturn::Send(value))
                            {
                                // Channel is closed, disconnect from the server
                                stream.shutdown(Shutdown::Both)?;
                                break;
                            }

                            // If the send failed, disconnect from the server
                            if error_occurred {
                                stream.shutdown(Shutdown::Both)?;
                                break;
                            }
                        }
                        ClientCommand::GetAddr => {
                            // Get the stream's address
                            let addr = stream.local_addr();

                            // Return the address
                            if let Err(_e) = client_command_receiver
                                .command_return(ClientCommandReturn::GetAddr(addr))
                            {
                                // Channel is closed, disconnect from the server
                                stream.shutdown(Shutdown::Both)?;
                                break;
                            }
                        }
                        ClientCommand::GetServerAddr => {
                            // Get the stream's address
                            let addr = stream.peer_addr();

                            // Return the address
                            if let Err(_e) = client_command_receiver
                                .command_return(ClientCommandReturn::GetServerAddr(addr))
                            {
                                // Channel is closed, disconnect from the server
                                stream.shutdown(Shutdown::Both)?;
                                break;
                            }
                        }
                    }
                }
            }
            Err(_e) => {
                // Client probably disconnected, exit
                stream.shutdown(Shutdown::Both)?;
                break;
            }
        }
    }

    // Send a disconnect event, ignoring send errors
    if let Err(_e) = client_event_sender.send(ClientEvent::Disconnect) {}

    Ok(())
}
