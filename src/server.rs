//! The server network interface.

use super::command_channel::*;
use super::util::*;
use serde::{de::DeserializeOwned, ser::Serialize};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;

pub enum ServerCommand<S>
where
    S: Serialize + Send + 'static,
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
    S: Serialize + Send + 'static,
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

pub enum ServerEvent<R>
where
    R: DeserializeOwned + Send + 'static,
{
    Connect { client_id: usize },
    Disconnect { client_id: usize },
    Receive { client_id: usize, data: R },
}

pub struct ServerHandle<S>
where
    S: Serialize + Send + 'static,
{
    server_command_sender: CommandChannelSender<ServerCommand<S>, ServerCommandReturn>,
    server_task_handle: JoinHandle<()>,
}

impl<S> ServerHandle<S>
where
    S: Serialize + Send + 'static,
{
    pub async fn stop(mut self) -> io::Result<()> {
        let value = self.server_command_sender.send(ServerCommand::Stop).await?;
        self.server_task_handle.await.unwrap();
        unwrap_enum!(value, ServerCommandReturn::Stop)
    }

    pub async fn send(&mut self, client_id: usize, data: S) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send(ServerCommand::Send { client_id, data })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::Send)
    }

    pub async fn send_all(&mut self, data: S) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send(ServerCommand::SendAll { data })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::SendAll)
    }

    pub async fn get_addr(&mut self) -> io::Result<SocketAddr> {
        let value = self
            .server_command_sender
            .send(ServerCommand::GetAddr)
            .await?;
        unwrap_enum!(value, ServerCommandReturn::GetAddr)
    }

    pub async fn get_client_addr(&mut self, client_id: usize) -> io::Result<SocketAddr> {
        let value = self
            .server_command_sender
            .send(ServerCommand::GetClientAddr { client_id })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::GetClientAddr)
    }

    pub async fn remove_client(&mut self, client_id: usize) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send(ServerCommand::RemoveClient { client_id })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::RemoveClient)
    }
}

pub struct Server<S, R>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    phantom_send: std::marker::PhantomData<S>,
    phantom_receive: std::marker::PhantomData<R>,
}

impl<S, R> Server<S, R>
where
    S: Serialize + Send + 'static,
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
            // Collection of channels for sending commands from the background server task to a background client task
            let mut client_command_channels: HashMap<
                usize,
                CommandChannelSender<ServerClientCommand<S>, ServerClientCommandReturn>,
            > = HashMap::new();
            // Background client task join handles
            let mut client_join_handles = vec![];
            // ID assigned to the next client
            let mut next_client_id = 0usize;

            // Server listener loop
            loop {
                // Await new clients connecting and commands from the server handle
                tokio::select! {
                    // Accept a connecting client
                    accept_value = listener.accept() => {
                        // Get the client socket, panicking if an error occurs
                        let (mut socket, _) = accept_value.unwrap();
                        // Channels for sending commands from the background server task to a background client task
                        let (client_command_sender, mut client_command_receiver) = command_channel();
                        // New client ID
                        let client_id = next_client_id.clone();
                        // Increment next client ID
                        next_client_id += 1;
                        // Clone the event sender so the background client tasks can send events
                        let server_client_event_sender = server_event_sender.clone();

                        // Start a background client task, saving the join handle for when the server is stopped
                        let client_task_handle = tokio::spawn(async move {
                            // Buffer in which to receive the size portion of a message
                            let mut size_buf = [0; LEN_SIZE];

                            // Client loop
                            loop {
                                // Await messages from the client and commands from the background server task
                                tokio::select! {
                                    // Read from the client socket
                                    read_value = socket.read(&mut size_buf) => {
                                        // Handle the bytes read from the socket
                                        let n = match read_value {
                                            Ok(0) => break, // TODO: disconnect, etc.
                                            Ok(n) => n,
                                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                                            Err(e) => panic!("{}", e),
                                        };
                                        assert_eq!(n, LEN_SIZE);
                                        // TODO: finish reading data from socket, send event through channel
                                        // TODO: change the above code such than on error or 0 bytes read, the client will be disconnected and the connection closed
                                        // TODO: read the docs to ensure that other behavior is not necessary when errors are returned
                                    }
                                    // Process a command sent to the client
                                    client_command_value = client_command_receiver.recv() => {
                                        // Handle the command, or lack thereof if the channel is closed
                                        match client_command_value {
                                            Ok(client_command) => {
                                                match client_command {
                                                    ServerClientCommand::Send { data } => {
                                                        // TODO: send data to client
                                                    },
                                                    ServerClientCommand::GetAddr => {
                                                        // TODO: get client's address
                                                    },
                                                    ServerClientCommand::Remove => {
                                                        // TODO: disconnect client
                                                    },
                                                }
                                            },
                                            Err(e) => break, // TODO: attempt to disconnect client
                                        }
                                    }
                                }
                            }
                        });

                        client_command_channels.insert(client_id, client_command_sender);
                        client_join_handles.push(client_task_handle);
                    }
                    // Process a command from the server handle
                    command_value = server_command_receiver.recv() => {
                        // Handle the command, or lack thereof if the channel is closed
                        match command_value {
                            Ok(command) => {
                                match command {
                                    ServerCommand::Stop => {
                                        // TODO: disconnect all clients, close listener, and break
                                    },
                                    ServerCommand::Send { client_id, data } => {
                                        // TODO: send data to client
                                    },
                                    ServerCommand::SendAll { data } => {
                                        // TODO: send data to all clients
                                    },
                                    ServerCommand::GetAddr => {
                                        // TODO: get server address
                                    },
                                    ServerCommand::GetClientAddr { client_id } => {
                                        // TODO: get client address
                                    },
                                    ServerCommand::RemoveClient { client_id } => {
                                        // TODO: disconnect client
                                    },
                                }
                            },
                            Err(e) => break, // TODO: disconnect all clients and listener
                        }
                    }
                }
            }

            // Join all background client tasks before exiting
            for handle in client_join_handles {
                handle.await.unwrap();
            }
        });

        let server_handle = ServerHandle {
            server_command_sender,
            server_task_handle,
        };

        Ok((server_handle, server_event_receiver))
    }
}
