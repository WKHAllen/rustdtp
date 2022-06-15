//! The server network interface.

use super::command_channel::*;
use super::util::*;
use serde::{de::DeserializeOwned, ser::Serialize};
use std::collections::HashMap;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::sync::mpsc::{channel, Receiver};
use tokio::task::JoinHandle;

pub enum ServerCommand<S>
where
    S: Serialize + Clone + Send + 'static,
{
    Stop,
    Send { client_id: usize, data: S },
    SendAll { data: S },
    GetAddr,
    GetClientAddr { client_id: usize },
    RemoveClient { client_id: usize },
}

pub enum ServerCommandReturn {
    Stop(io::Result<()>),
    Send(io::Result<()>),
    SendAll(io::Result<()>),
    GetAddr(io::Result<SocketAddr>),
    GetClientAddr(io::Result<SocketAddr>),
    RemoveClient(io::Result<()>),
}

pub enum ServerClientCommand<S>
where
    S: Serialize + Clone + Send + 'static,
{
    Send { data: S },
    GetAddr,
    Remove,
}

pub enum ServerClientCommandReturn {
    Send(io::Result<()>),
    GetAddr(io::Result<SocketAddr>),
    Remove(io::Result<()>),
}

#[derive(Debug)]
pub enum ServerEvent<R>
where
    R: DeserializeOwned + Send + 'static,
{
    Connect { client_id: usize },
    Disconnect { client_id: usize },
    Receive { client_id: usize, data: R },
    Stop,
}

pub struct ServerHandle<S>
where
    S: Serialize + Clone + Send + 'static,
{
    server_command_sender: CommandChannelSender<ServerCommand<S>, ServerCommandReturn>,
    server_task_handle: JoinHandle<io::Result<()>>,
}

impl<S> ServerHandle<S>
where
    S: Serialize + Clone + Send + 'static,
{
    pub async fn stop(mut self) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::Stop)
            .await?;
        self.server_task_handle.await.unwrap()?;
        unwrap_enum!(value, ServerCommandReturn::Stop)
    }

    pub async fn send(&mut self, client_id: usize, data: S) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::Send { client_id, data })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::Send)
    }

    pub async fn send_all(&mut self, data: S) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::SendAll { data })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::SendAll)
    }

    pub async fn get_addr(&mut self) -> io::Result<SocketAddr> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::GetAddr)
            .await?;
        unwrap_enum!(value, ServerCommandReturn::GetAddr)
    }

    pub async fn get_client_addr(&mut self, client_id: usize) -> io::Result<SocketAddr> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::GetClientAddr { client_id })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::GetClientAddr)
    }

    pub async fn remove_client(&mut self, client_id: usize) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::RemoveClient { client_id })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::RemoveClient)
    }
}

pub struct Server<S, R>
where
    S: Serialize + Clone + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    phantom_send: PhantomData<S>,
    phantom_receive: PhantomData<R>,
}

impl<S, R> Server<S, R>
where
    S: Serialize + Clone + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    pub async fn start<A>(addr: A) -> io::Result<(ServerHandle<S>, Receiver<ServerEvent<R>>)>
    where
        A: ToSocketAddrs,
    {
        // Server TCP listener
        let listener = TcpListener::bind(addr).await?;
        // Channels for sending commands from the server handle to the background server task
        let (server_command_sender, mut server_command_receiver) = command_channel();
        // Channels for sending event notifications from the background server task
        let (server_event_sender, server_event_receiver) = channel(CHANNEL_BUFFER_SIZE);

        // Start the background server task, saving the join handle for when the server is stopped
        let server_task_handle = tokio::spawn(async move {
            // ID assigned to the next client
            let mut next_client_id = 0usize;
            // Collection of channels for sending commands from the background server task to a background client task
            let mut client_command_senders: HashMap<
                usize,
                CommandChannelSender<ServerClientCommand<S>, ServerClientCommandReturn>,
            > = HashMap::new();
            // Background client task join handles
            let mut client_join_handles: HashMap<usize, JoinHandle<io::Result<()>>> =
                HashMap::new();
            // Channel for indicating that a client needs to be cleaned up after
            let (server_client_cleanup_sender, mut server_client_cleanup_receiver) =
                channel::<usize>(CHANNEL_BUFFER_SIZE);

            // Wrap server loop in a block to catch all exit scenarios
            let server_exit = {
                // Server loop
                loop {
                    // Await new clients connecting,
                    // commands from the server handle,
                    // and notifications of clients disconnecting
                    tokio::select! {
                        // Accept a connecting client
                        accept_value = listener.accept() => {
                            // Get the client socket, panicking if an error occurs
                            let (mut socket, _) = accept_value?;
                            // Channels for sending commands from the background server task to a background client task
                            let (client_command_sender, mut client_command_receiver) = command_channel();
                            // New client ID
                            let client_id = next_client_id.clone();
                            // Increment next client ID
                            next_client_id += 1;
                            // Clone the event sender so the background client tasks can send events
                            let server_client_event_sender = server_event_sender.clone();
                            // Clone the client cleanup sender to the background client tasks can be cleaned up properly
                            let client_cleanup_sender = server_client_cleanup_sender.clone();

                            // Start a background client task, saving the join handle for when the server is stopped
                            let client_task_handle = tokio::spawn(async move {
                                // Wrap client loop in a block to catch all exit scenarios
                                let client_exit = {
                                    // Buffer in which to receive the size portion of a message
                                    let mut size_buffer = [0; LEN_SIZE];

                                    // Client loop
                                    loop {
                                        // Await messages from the client
                                        // and commands from the background server task
                                        tokio::select! {
                                            // Read the size portion from the client socket
                                            read_value = socket.read(&mut size_buffer) => {
                                                // Return an error if the socket could not be read
                                                let n_size = read_value?;

                                                // If there were no bytes read, or if there were fewer bytes read than there
                                                // should have been, close the socket
                                                if n_size != LEN_SIZE {
                                                    socket.shutdown().await?;
                                                    break;
                                                };

                                                // Decode the size portion of the message
                                                let data_size = decode_message_size(&size_buffer);
                                                // Initialize the buffer for the data portion of the message
                                                let mut data_buffer = vec![0; data_size];

                                                // Read the data portion from the client socket, returning an error if the
                                                // socket could not be read
                                                let n_data = socket.read(&mut data_buffer).await?;

                                                // If there were no bytes read, or if there were fewer bytes read than there
                                                // should have been, close the socket
                                                if n_data != data_size {
                                                    socket.shutdown().await?;
                                                    break;
                                                }

                                                // Deserialize the message data
                                                if let Ok(data) = serde_json::from_slice(&data_buffer) {
                                                    // Send an event to note that a piece of data has been received from
                                                    // a client
                                                    if let Err(_e) = server_client_event_sender.send(ServerEvent::Receive { client_id, data }).await {
                                                        // Sending failed, disconnect the client
                                                        socket.shutdown().await?;
                                                        break;
                                                    }
                                                } else {
                                                    // Deserialization failed, disconnect the client
                                                    socket.shutdown().await?;
                                                    break;
                                                }
                                            }
                                            // Process a command sent to the client
                                            client_command_value = client_command_receiver.recv_command() => {
                                                // Handle the command, or lack thereof if the channel is closed
                                                match client_command_value {
                                                    Ok(client_command) => {
                                                        // Process the command
                                                        match client_command {
                                                            ServerClientCommand::Send { data } => {
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

                                                                    // Write the data to the client socket
                                                                    let n = socket.write(&buffer).await?;

                                                                    // If there were no bytes written, or if there were fewer
                                                                    // bytes written than there should have been, close the
                                                                    // socket
                                                                    if n != buffer.len() {
                                                                        generic_io_error("failed to write data to socket")
                                                                    } else {
                                                                        io::Result::Ok(())
                                                                    }
                                                                };

                                                                let error_occurred = value.is_err();

                                                                // Return the status of the send operation
                                                                if let Err(_e) = client_command_receiver.command_return(ServerClientCommandReturn::Send(value)).await {
                                                                    // Channel is closed, disconnect the client
                                                                    socket.shutdown().await?;
                                                                    break;
                                                                }

                                                                // If the send failed, disconnect the client
                                                                if error_occurred {
                                                                    socket.shutdown().await?;
                                                                    break;
                                                                }
                                                            },
                                                            ServerClientCommand::GetAddr => {
                                                                // Get the client socket's address
                                                                let addr = socket.peer_addr();

                                                                // Return the address
                                                                if let Err(_e) = client_command_receiver.command_return(ServerClientCommandReturn::GetAddr(addr)).await {
                                                                    // Channel is closed, disconnect the client
                                                                    socket.shutdown().await?;
                                                                    break;
                                                                }
                                                            },
                                                            ServerClientCommand::Remove => {
                                                                // Disconnect the client
                                                                let value = socket.shutdown().await;

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
                                                        socket.shutdown().await?;
                                                        break;
                                                    },
                                                }
                                            }
                                        }
                                    }

                                    io::Result::Ok(())
                                };

                                // Tell the server to clean up after the client, ignoring failures, since a failure
                                // indicates that the server has probably closed
                                if let Err(_e) = client_cleanup_sender.send(client_id).await {}

                                // Return client loop result
                                client_exit
                            });

                            // Keep track of client command senders
                            client_command_senders.insert(client_id, client_command_sender);
                            // Keep track of client task handles
                            client_join_handles.insert(client_id, client_task_handle);

                            // Send an event to note that a client has connected successfully
                            if let Err(_e) = server_event_sender.send(ServerEvent::Connect { client_id }).await {
                                // Server is probably closed
                                break;
                            };
                        }
                        // Process a command from the server handle
                        command_value = server_command_receiver.recv_command() => {
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
                                            let value = {
                                                for (_client_id, client_command_sender) in client_command_senders.iter_mut() {
                                                    let data_clone = data.clone();

                                                    match client_command_sender.send_command(ServerClientCommand::Send { data: data_clone }).await {
                                                        Ok(return_value) => unwrap_enum!(return_value, ServerClientCommandReturn::Send),
                                                        Err(_e) => {
                                                            // The channel is closed, and the client has probably been
                                                            // disconnected, so the error can be ignored
                                                            Ok(())
                                                        },
                                                    }?;
                                                };

                                                io::Result::Ok(())
                                            };

                                            // If a command fails to send, the client has probably disconnected,
                                            // and the error can be ignored
                                            if let Ok(_) = server_command_receiver.command_return(ServerCommandReturn::SendAll(value)).await {}
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
                        disconnecting_client_id = server_client_cleanup_receiver.recv() => {
                            match disconnecting_client_id {
                                Some(client_id) => {
                                    // Remove the client's command sender, which will be dropped after this block ends
                                    client_command_senders.remove(&client_id);

                                    // Remove the client's join handle
                                    if let Some(handle) = client_join_handles.remove(&client_id) {
                                        // Join the client's handle
                                        handle.await.unwrap()?;
                                    }

                                    // Send an event to note that a client has disconnected
                                    if let Err(_e) = server_event_sender.send(ServerEvent::Disconnect { client_id }).await {
                                        // Server is probably closed, exit
                                        break;
                                    }
                                },
                                None => {
                                    // Server is probably closed, exit
                                    break;
                                },
                            }
                        }
                    }
                }

                io::Result::Ok(())
            };

            // Send a remove command to all clients
            for (_client_id, mut client_command_sender) in client_command_senders {
                // If a command fails to send, the client has probably disconnected already,
                // and the error can be ignored
                if let Ok(_) = client_command_sender
                    .send_command(ServerClientCommand::Remove)
                    .await
                {}
            }

            // Join all background client tasks before exiting
            for (_client_id, handle) in client_join_handles {
                handle.await.unwrap()?;
            }

            // Send a stop event, ignoring send errors
            if let Err(_e) = server_event_sender.send(ServerEvent::Stop).await {}

            // Return server loop result
            server_exit
        });

        // Create a handle for the server
        let server_handle = ServerHandle {
            server_command_sender,
            server_task_handle,
        };

        Ok((server_handle, server_event_receiver))
    }
}
