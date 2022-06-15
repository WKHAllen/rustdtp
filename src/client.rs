//! The client network interface.

use super::command_channel::*;
use super::util::*;
use serde::{de::DeserializeOwned, ser::Serialize};
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::mpsc::{channel, Receiver};
use tokio::task::JoinHandle;

pub enum ClientCommand<S>
where
    S: Serialize + Send + 'static,
{
    Disconnect,
    Send { data: S },
    GetAddr,
    GetServerAddr,
}

pub enum ClientCommandReturn {
    Disconnect(io::Result<()>),
    Send(io::Result<()>),
    GetAddr(io::Result<SocketAddr>),
    GetServerAddr(io::Result<SocketAddr>),
}

#[derive(Debug)]
pub enum ClientEvent<R>
where
    R: DeserializeOwned + Send + 'static,
{
    Receive { data: R },
    Disconnect,
}

pub struct ClientHandle<S>
where
    S: Serialize + Send + 'static,
{
    client_command_sender: CommandChannelSender<ClientCommand<S>, ClientCommandReturn>,
    client_task_handle: JoinHandle<io::Result<()>>,
}

impl<S> ClientHandle<S>
where
    S: Serialize + Send + 'static,
{
    pub async fn disconnect(mut self) -> io::Result<()> {
        let value = self
            .client_command_sender
            .send_command(ClientCommand::Disconnect)
            .await?;
        self.client_task_handle.await.unwrap()?;
        unwrap_enum!(value, ClientCommandReturn::Disconnect)
    }

    pub async fn send(&mut self, data: S) -> io::Result<()> {
        let value = self
            .client_command_sender
            .send_command(ClientCommand::Send { data })
            .await?;
        unwrap_enum!(value, ClientCommandReturn::Send)
    }

    pub async fn get_addr(&mut self) -> io::Result<SocketAddr> {
        let value = self
            .client_command_sender
            .send_command(ClientCommand::GetAddr)
            .await?;
        unwrap_enum!(value, ClientCommandReturn::GetAddr)
    }

    pub async fn get_server_addr(&mut self) -> io::Result<SocketAddr> {
        let value = self
            .client_command_sender
            .send_command(ClientCommand::GetServerAddr)
            .await?;
        unwrap_enum!(value, ClientCommandReturn::GetServerAddr)
    }
}

pub struct Client<S, R>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    phantom_send: PhantomData<S>,
    phantom_receive: PhantomData<R>,
}

impl<S, R> Client<S, R>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    pub async fn connect<A>(addr: A) -> io::Result<(ClientHandle<S>, Receiver<ClientEvent<R>>)>
    where
        A: ToSocketAddrs,
    {
        // Client TCP stream
        let mut stream = TcpStream::connect(addr).await?;
        // Channels for sending commands from the client handle to the background client task
        let (client_command_sender, mut client_command_receiver) = command_channel();
        // Channels for sending event notifications from the background client task
        let (client_event_sender, client_event_receiver) = channel(CHANNEL_BUFFER_SIZE);

        // Start the background client task, saving the join handle for when the client disconnects
        let client_task_handle = tokio::spawn(async move {
            // Wrap client loop in a block to catch all exit scenarios
            let client_exit = {
                // Buffer in which to receive the size portion of a message
                let mut size_buffer = [0; LEN_SIZE];

                // Client loop
                loop {
                    // Await messages from the server
                    // and commands from the client handle
                    tokio::select! {
                        // Read the size portion from the stream
                        read_value = stream.read(&mut size_buffer) => {
                            // Return an error if the stream could not be read
                            let n_size = read_value?;

                            // If there were no bytes read, or if there were fewer bytes read than there
                            // should have been, close the stream
                            if n_size != LEN_SIZE {
                                stream.shutdown().await?;
                                break;
                            }

                            // Decode the size portion of the message
                            let data_size = decode_message_size(&size_buffer);
                            // Initialize the buffer for the data portion of the message
                            let mut data_buffer = vec![0; data_size];

                            // Read the data portion from the client stream, returning an error if the
                            // stream could not be read
                            let n_data = stream.read(&mut data_buffer).await?;

                            // If there were no bytes read, or if there were fewer bytes read than there
                            // should have been, close the stream
                            if n_data != data_size {
                                stream.shutdown().await?;
                                break;
                            }

                            // Deserialize the message data
                            if let Ok(data) = serde_json::from_slice(&data_buffer) {
                                // Send an event to note that a piece of data has been received from
                                // the server
                                if let Err(_e) = client_event_sender.send(ClientEvent::Receive { data }).await {
                                    // Sending failed, disconnect
                                    stream.shutdown().await?;
                                    break;
                                }
                            } else {
                                // Deserialization failed, disconnect
                                stream.shutdown().await?;
                                break;
                            }
                        }
                        // Process a command from the client handle
                        command_value = client_command_receiver.recv_command() => {
                            // Handle the command, or lack thereof if the channel is closed
                            match command_value {
                                Ok(command) => {
                                    match command {
                                        ClientCommand::Disconnect => {
                                            // Disconnect from the server
                                            let value = stream.shutdown().await;

                                            // If a command fails to send, the client has already disconnected,
                                            // and the error can be ignored.
                                            // It should be noted that this is not where the disconnect method actually returns
                                            // its `Result`. This immediately returns with an `Ok` status. The real return
                                            // value is the `Result` returned from the client task join handle.
                                            if let Ok(_) = client_command_receiver.command_return(ClientCommandReturn::Disconnect(value)).await {}

                                            // Break the client loop
                                            break;
                                        },
                                        ClientCommand::Send { data } => {
                                            let value = {
                                                // Serialize the data
                                                let data_buffer = serde_json::to_vec(&data)?;
                                                // Encode the message size to a buffer
                                                let size_buffer = encode_message_size(data_buffer.len());

                                                // Initialize the message buffer
                                                let mut buffer = vec![];
                                                // Extend the buffer to contain the payload size
                                                buffer.extend_from_slice(&size_buffer);
                                                // Extend the buffer to contain the payload data
                                                buffer.extend(&data_buffer);

                                                // Write the data to the stream
                                                let n = stream.write(&buffer).await?;

                                                // If there were no bytes written, or if there were fewer
                                                // bytes written than there should have been, close the
                                                // stream
                                                if n != buffer.len() {
                                                    generic_io_error("failed to write data to stream")
                                                } else {
                                                    io::Result::Ok(())
                                                }
                                            };

                                            let error_occurred = value.is_err();

                                            // Return the status of the send operation
                                            if let Err(_e) = client_command_receiver.command_return(ClientCommandReturn::Send(value)).await {
                                                // Channel is closed, disconnect from the server
                                                stream.shutdown().await?;
                                                break;
                                            }

                                            // If the send failed, disconnect from the server
                                            if error_occurred {
                                                stream.shutdown().await?;
                                                break;
                                            }
                                        },
                                        ClientCommand::GetAddr => {
                                            // Get the stream's address
                                            let addr = stream.local_addr();

                                            // Return the address
                                            if let Err(_e) = client_command_receiver.command_return(ClientCommandReturn::GetAddr(addr)).await {
                                                // Channel is closed, disconnect from the server
                                                stream.shutdown().await?;
                                                break;
                                            }
                                        },
                                        ClientCommand::GetServerAddr => {
                                            // Get the stream's address
                                            let addr = stream.peer_addr();

                                            // Return the address
                                            if let Err(_e) = client_command_receiver.command_return(ClientCommandReturn::GetServerAddr(addr)).await {
                                                // Channel is closed, disconnect from the server
                                                stream.shutdown().await?;
                                                break;
                                            }
                                        },
                                    }
                                },
                                Err(_e) => {
                                    // Client probably disconnected, exit
                                    stream.shutdown().await?;
                                    break;
                                }
                            }
                        }
                    }
                }

                // Send a disconnect event, ignoring send errors
                if let Err(_e) = client_event_sender.send(ClientEvent::Disconnect).await {}

                io::Result::Ok(())
            };

            // Return client loop result
            client_exit
        });

        // Create a handle for the client
        let client_handle = ClientHandle {
            client_command_sender,
            client_task_handle,
        };

        Ok((client_handle, client_event_receiver))
    }
}
