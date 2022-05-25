//! The server network interface.

use crate::util::*;
use std::collections::HashMap;
use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// A command sent from the server handle to the server.
enum ServerCommand {
    Stop,
    Send { data: Vec<u8>, client_id: usize },
    SendAll { data: Vec<u8> },
    Serving,
    GetAddr,
    GetClientAddr { client_id: usize },
    RemoveClient { client_id: usize },
}

/// The return value of a command executed on the server.
enum ServerCommandReturn {
    Stop(io::Result<()>),
    Send(io::Result<()>),
    SendAll(io::Result<()>),
    Serving(bool),
    GetAddr(io::Result<SocketAddr>),
    GetClientAddr(io::Result<SocketAddr>),
    RemoveClient(io::Result<()>),
}

/// The network server. Event callbacks must be provided via chaining:
/// 
/// ```no_run
/// use rustdtp::Server;
/// 
/// let server = Server::new()
///     .on_receive(|client_id, data| {
///         println!("Message from client #{}: {:?}", client_id, data);
///     })
///     .on_connect(|client_id| {
///         println!("Client #{} connected", client_id);
///     })
///     .on_disconnect(|client_id| {
///         println!("Client #{} disconnected", client_id);
///     })
///     .start_default()
///     .unwrap();
/// ```
#[derive(Debug)]
pub struct Server<R, C, D>
where
    R: Fn(usize, &[u8]) + Clone + Send + 'static,
    C: Fn(usize) + Clone + Send + 'static,
    D: Fn(usize) + Clone + Send + 'static,
{
    on_receive: Option<R>,
    on_connect: Option<C>,
    on_disconnect: Option<D>,
    serving: bool,
    shutdown: bool,
    clients: HashMap<usize, TcpStream>,
    next_client_id: usize,
    cmd_receiver: mpsc::Receiver<ServerCommand>,
    cmd_return_sender: mpsc::Sender<ServerCommandReturn>,
}

impl<R, C, D> Server<R, C, D>
where
    R: Fn(usize, &[u8]) + Clone + Send + 'static,
    C: Fn(usize) + Clone + Send + 'static,
    D: Fn(usize) + Clone + Send + 'static,
{
    /// Create a new server builder instance.
    pub fn new() -> ServerBuilder<R, C, D> {
        ServerBuilder::new()
    }

    /// Start a server.
    /// 
    /// `listener`: the server's TCP listener.
    /// 
    /// Returns a result of the error variant if an error occurred while serving.
    pub fn start(&mut self, listener: TcpListener) -> io::Result<()> {
        if self.serving {
            return generic_error(*Error::AlreadyServing);
        }

        self.serving = true;

        self.serve(listener)
    }

    /// Perform server operations.
    /// 
    /// `listener`: the server's TCP listener.
    /// 
    /// Returns a result of the error variant if an error occurred while serving.
    fn serve(&mut self, listener: TcpListener) -> io::Result<()> {
        for stream in listener.incoming() {
            if !self.serving {
                if !self.shutdown {
                    self.serving = true;
                    self.stop()?;
                }

                return Ok(());
            }

            let result = match stream {
                Ok(conn) => {
                    let client_id = self.next_client_id;
                    self.next_client_id += 1;
                    conn.set_nonblocking(true)?;

                    self.clients.insert(client_id, conn);

                    match &self.on_connect {
                        Some(on_connect) => on_connect(client_id),
                        None => (),
                    }

                    Ok(())
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if self.serving {
                        Ok(())
                    } else {
                        generic_error(*Error::ServerClosed)
                    }
                }
                Err(e) => Err(e),
            };

            if result.is_err() {
                let result_err = result.err().unwrap();

                if result_err.kind() == io::ErrorKind::Other {
                    return Ok(());
                } else {
                    return Err(result_err);
                }
            }

            let clients_to_remove = self.serve_clients()?;

            for client_id in clients_to_remove {
                self.clients.remove(&client_id);
            }

            match self.cmd_receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(cmd) => self.execute_command(cmd, &listener),
                Err(_) => Ok(()),
            }?;
        }

        unreachable!();
    }

    /// Serve a connected client.
    /// 
    /// `client_id`: the ID of the client.
    /// 
    /// Returns a result containing a boolean representing whether the client is still connected, or the error variant if a network error occurred.
    fn serve_client(&self, client_id: usize) -> io::Result<bool> {
        match self.clients.get(&client_id) {
            Some(mut client) => {
                let mut size_buffer = [0; LEN_SIZE];
                let result = match client.read(&mut size_buffer) {
                    Ok(size_len) => {
                        if size_len == 0 {
                            match &self.on_disconnect {
                                Some(on_disconnect) => on_disconnect(client_id),
                                None => (),
                            }

                            client.shutdown(Shutdown::Both)?;

                            return Ok(false);
                        }

                        assert_eq!(size_len, LEN_SIZE);

                        let msg_size = decode_message_size(&size_buffer);
                        let mut buffer = vec![0; msg_size];

                        match client.read(&mut buffer) {
                            Ok(len) => {
                                assert_eq!(len, msg_size);

                                let msg = buffer.as_slice();

                                match &self.on_receive {
                                    Some(on_receive) => on_receive(client_id, msg),
                                    None => (),
                                }

                                Ok(())
                            }
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                if self.serving {
                                    Ok(())
                                } else {
                                    generic_error(*Error::ServerClosed)
                                }
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        if self.serving {
                            Ok(())
                        } else {
                            generic_error(*Error::ServerClosed)
                        }
                    }
                    Err(e) => Err(e),
                };

                if result.is_err() {
                    let result_err = result.err().unwrap();

                    if result_err.kind() == io::ErrorKind::Other {
                        return Ok(true);
                    } else {
                        return Err(result_err);
                    }
                }

                Ok(true)
            }
            None => generic_error(*Error::InvalidClientID),
        }
    }

    /// Serve all connected clients.
    /// 
    /// Returns a result containing a list of IDs of clients to remove, or the error variant if an error occurred while serving a client.
    fn serve_clients(&self) -> io::Result<Vec<usize>> {
        let mut clients_to_remove = vec![];

        for (client_id, _) in &self.clients {
            if !self.serve_client(*client_id)? {
                clients_to_remove.push(*client_id);
            };
        }

        Ok(clients_to_remove)
    }

    /// Stop the server, disconnect all clients, and shut down all network connections.
    /// 
    /// Returns a result of the error variant if an error occurred while disconnecting clients.
    pub fn stop(&mut self) -> io::Result<()> {
        if !self.serving {
            return generic_error(*Error::NotServing);
        }

        self.serving = false;

        for (_, client) in &self.clients {
            client.shutdown(Shutdown::Both)?;
        }

        self.clients.clear();

        self.shutdown = true;

        Ok(())
    }

    /// Send data to a client.
    /// 
    /// `data`: the data to send.
    /// `client_id`: the ID of the client to send the data to.
    /// 
    /// Returns a result of the error variant if an error occurred while sending data.
    pub fn send(&self, data: &[u8], client_id: usize) -> io::Result<()> {
        if !self.serving {
            return generic_error(*Error::NotServing);
        }

        match self.clients.get(&client_id) {
            Some(mut client) => {
                let size = encode_message_size(data.len());
                let mut buffer = vec![];
                buffer.extend_from_slice(&size);
                buffer.extend_from_slice(data);

                assert_eq!(buffer.len(), data.len() + LEN_SIZE);

                client.write(&buffer)?;
                Ok(())
            }
            None => generic_error(*Error::InvalidClientID),
        }
    }

    /// Send data to all clients.
    /// 
    /// `data`: the data to send.
    /// 
    /// Returns a result of the error variant if an error occurred while sending data.
    pub fn send_all(&self, data: &[u8]) -> io::Result<()> {
        for (client_id, _) in &self.clients {
            self.send(data, *client_id)?;
        }

        Ok(())
    }

    /// Check if the server is serving.
    /// 
    /// Returns a boolean value representing whether the server is serving.
    pub fn serving(&self) -> bool {
        self.serving
    }

    /// Get the address the server is listening on.
    /// 
    /// `listener`: the server's TCP listener.
    /// 
    /// Returns a result containing the address the server is listening on, or the error variant if the server is not serving.
    pub fn get_addr(&self, listener: &TcpListener) -> io::Result<SocketAddr> {
        if !self.serving {
            return generic_error(*Error::NotServing);
        }

        listener.local_addr()
    }

    /// Get the address of a connected client.
    /// 
    /// `client_id`: the ID of the client.
    /// 
    /// Returns a result containing the address of the client, or the error variant if the client ID is invalid.
    pub fn get_client_addr(&self, client_id: usize) -> io::Result<SocketAddr> {
        if !self.serving {
            return generic_error(*Error::NotServing);
        }

        match self.clients.get(&client_id) {
            Some(client) => client.peer_addr(),
            None => generic_error(*Error::InvalidClientID),
        }
    }

    /// Disconnect a client from the server.
    /// 
    /// `client_id`: the ID of the client.
    /// 
    /// Returns a result of the error variant if an error occurred while disconnecting the client.
    pub fn remove_client(&mut self, client_id: usize) -> io::Result<()> {
        if !self.serving {
            return generic_error(*Error::NotServing);
        }

        match self.clients.get(&client_id) {
            Some(client) => {
                client.shutdown(Shutdown::Both)?;
                self.clients.remove(&client_id);
                Ok(())
            }
            None => generic_error(*Error::InvalidClientID),
        }
    }

    /// Execute a command from the server handle.
    /// 
    /// `command`: the command to execute.
    /// `listener`: the server's TCP listener.
    /// 
    /// Returns a result of the error variant if an error occurred while executing the command.
    fn execute_command(
        &mut self,
        command: ServerCommand,
        listener: &TcpListener,
    ) -> io::Result<()> {
        match match command {
            ServerCommand::Stop => {
                let ret = self.stop();
                self.cmd_return_sender.send(ServerCommandReturn::Stop(ret))
            }
            ServerCommand::Send { data, client_id } => self
                .cmd_return_sender
                .send(ServerCommandReturn::Send(self.send(&data, client_id))),
            ServerCommand::SendAll { data } => self
                .cmd_return_sender
                .send(ServerCommandReturn::SendAll(self.send_all(data.as_slice()))),
            ServerCommand::Serving => self
                .cmd_return_sender
                .send(ServerCommandReturn::Serving(self.serving())),
            ServerCommand::GetAddr => self
                .cmd_return_sender
                .send(ServerCommandReturn::GetAddr(self.get_addr(listener))),
            ServerCommand::GetClientAddr { client_id } => {
                self.cmd_return_sender
                    .send(ServerCommandReturn::GetClientAddr(
                        self.get_client_addr(client_id),
                    ))
            }
            ServerCommand::RemoveClient { client_id } => {
                let ret = self.remove_client(client_id);
                self.cmd_return_sender
                    .send(ServerCommandReturn::RemoveClient(ret))
            }
        } {
            Ok(()) => Ok(()),
            Err(err) => generic_error(err),
        }
    }
}

impl<R, C, D> Drop for Server<R, C, D>
where
    R: Fn(usize, &[u8]) + Clone + Send + 'static,
    C: Fn(usize) + Clone + Send + 'static,
    D: Fn(usize) + Clone + Send + 'static,
{
    /// Stop the server and wait for it to fully shut down before dropping it.
    fn drop(&mut self) {
        self.serving = false;

        while !self.shutdown {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// A handle to a running server.
#[derive(Debug)]
pub struct ServerHandle {
    cmd_sender: mpsc::Sender<ServerCommand>,
    cmd_return_receiver: mpsc::Receiver<ServerCommandReturn>,
}

impl ServerHandle {
    /// Stop the server, disconnect all clients, and shut down all network connections.
    /// 
    /// Returns a result of the error variant if an error occurred while disconnecting clients.
    pub fn stop(&self) -> io::Result<()> {
        match self.cmd_sender.send(ServerCommand::Stop) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ServerCommandReturn::Stop(value) => value,
                    _ => generic_error(*Error::ChannelWrongResponse),
                },
                Err(_) => generic_error(*Error::NotServing),
            },
            Err(_) => generic_error(*Error::NotServing),
        }
    }

    /// Send data to a client.
    /// 
    /// `data`: the data to send.
    /// `client_id`: the ID of the client to send the data to.
    /// 
    /// Returns a result of the error variant if an error occurred while sending data.
    pub fn send(&self, data: &[u8], client_id: usize) -> io::Result<()> {
        match self.cmd_sender.send(ServerCommand::Send {
            data: data.to_vec(),
            client_id,
        }) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ServerCommandReturn::Send(value) => value,
                    _ => generic_error(*Error::ChannelWrongResponse),
                },
                Err(_) => generic_error(*Error::NotServing),
            },
            Err(_) => generic_error(*Error::NotServing),
        }
    }

    /// Send data to all clients.
    /// 
    /// `data`: the data to send.
    /// 
    /// Returns a result of the error variant if an error occurred while sending data.
    pub fn send_all(&self, data: &[u8]) -> io::Result<()> {
        match self.cmd_sender.send(ServerCommand::SendAll {
            data: data.to_vec(),
        }) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ServerCommandReturn::SendAll(value) => value,
                    _ => generic_error(*Error::ChannelWrongResponse),
                },
                Err(_) => generic_error(*Error::NotServing),
            },
            Err(_) => generic_error(*Error::NotServing),
        }
    }

    /// Check if the server is serving.
    /// 
    /// Returns a result containing a boolean value representing whether the server is serving, or the error variant if a channel error occurred.
    pub fn serving(&self) -> io::Result<bool> {
        match self.cmd_sender.send(ServerCommand::Serving) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ServerCommandReturn::Serving(value) => Ok(value),
                    _ => generic_error(*Error::ChannelWrongResponse),
                },
                Err(_) => Ok(false),
            },
            Err(_) => Ok(false),
        }
    }

    /// Get the address the server is listening on.
    /// 
    /// Returns a result containing the address the server is listening on, or the error variant if the server is not serving.
    pub fn get_addr(&self) -> io::Result<SocketAddr> {
        match self.cmd_sender.send(ServerCommand::GetAddr) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ServerCommandReturn::GetAddr(value) => value,
                    _ => generic_error(*Error::ChannelWrongResponse),
                },
                Err(_) => generic_error(*Error::NotServing),
            },
            Err(_) => generic_error(*Error::NotServing),
        }
    }

    /// Get the address of a connected client.
    /// 
    /// `client_id`: the ID of the client.
    /// 
    /// Returns a result containing the address of the client, or the error variant if the client ID is invalid.
    pub fn get_client_addr(&self, client_id: usize) -> io::Result<SocketAddr> {
        match self
            .cmd_sender
            .send(ServerCommand::GetClientAddr { client_id })
        {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ServerCommandReturn::GetClientAddr(value) => value,
                    _ => generic_error(*Error::ChannelWrongResponse),
                },
                Err(_) => generic_error(*Error::NotServing),
            },
            Err(_) => generic_error(*Error::NotServing),
        }
    }

    /// Disconnect a client from the server.
    /// 
    /// `client_id`: the ID of the client.
    /// 
    /// Returns a result of the error variant if an error occurred while disconnecting the client.
    pub fn remove_client(&self, client_id: usize) -> io::Result<()> {
        match self
            .cmd_sender
            .send(ServerCommand::RemoveClient { client_id })
        {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ServerCommandReturn::RemoveClient(value) => value,
                    _ => generic_error(*Error::ChannelWrongResponse),
                },
                Err(_) => generic_error(*Error::NotServing),
            },
            Err(_) => generic_error(*Error::NotServing),
        }
    }
}

impl Drop for ServerHandle {
    /// Stop the server and wait for it to fully shut down before dropping the handle to it.
    fn drop(&mut self) {
        if self.serving().unwrap() {
            self.stop().unwrap();
        }
    }
}

/// A server builder. The event callback methods must all be chained before the server can be built. The `start` methods build and start the server.
#[derive(Debug)]
pub struct ServerBuilder<R, C, D>
where
    R: Fn(usize, &[u8]) + Clone + Send + 'static,
    C: Fn(usize) + Clone + Send + 'static,
    D: Fn(usize) + Clone + Send + 'static,
{
    on_receive: Option<R>,
    on_connect: Option<C>,
    on_disconnect: Option<D>,
}

impl<R, C, D> ServerBuilder<R, C, D>
where
    R: Fn(usize, &[u8]) + Clone + Send + 'static,
    C: Fn(usize) + Clone + Send + 'static,
    D: Fn(usize) + Clone + Send + 'static,
{
    /// Create a new server builder instance.
    pub fn new() -> Self {
        Self {
            on_receive: None,
            on_connect: None,
            on_disconnect: None,
        }
    }

    /// Register the receive event callback.
    /// 
    /// `on_receive`: called when the server receives data from a client.
    pub fn on_receive(&mut self, on_receive: R) -> &mut Self {
        self.on_receive = Some(on_receive);
        self
    }

    /// Register the connect event callback.
    /// 
    /// `on_connect`: called when a client has connected.
    pub fn on_connect(&mut self, on_connect: C) -> &mut Self {
        self.on_connect = Some(on_connect);
        self
    }

    /// Register the disconnect event callback.
    /// 
    /// `on_disconnect`: called when a client has disconnected.
    pub fn on_disconnect(&mut self, on_disconnect: D) -> &mut Self {
        self.on_disconnect = Some(on_disconnect);
        self
    }

    /// Build and start the server.
    /// 
    /// `host`: the host address for the server to listen on.
    /// `port`: the port for the server to listen on.
    /// 
    /// Returns a result containing a handle to the server, or the error variant if an error occurred while starting the server.
    pub fn start(&mut self, host: &'static str, port: u16) -> io::Result<ServerHandle> {
        let (cmd_sender, cmd_receiver) = mpsc::channel();
        let (cmd_return_sender, cmd_return_receiver) = mpsc::channel();

        let addr = format!("{}:{}", host, port);
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;

        let mut server = Server {
            on_receive: self.on_receive.clone(),
            on_connect: self.on_connect.clone(),
            on_disconnect: self.on_disconnect.clone(),
            serving: false,
            shutdown: false,
            next_client_id: 0,
            clients: HashMap::new(),
            cmd_receiver,
            cmd_return_sender,
        };

        thread::spawn(move || {
            server.start(listener).unwrap();
        });

        Ok(ServerHandle {
            cmd_sender,
            cmd_return_receiver,
        })
    }

    /// Build and start the server, defaulting to host "0.0.0.0".
    /// 
    /// `port`: the port for the server to listen on.
    /// 
    /// Returns a result containing a handle to the server, or the error variant if an error occurred while starting the server.
    pub fn start_default_host(&mut self, port: u16) -> io::Result<ServerHandle> {
        self.start(DEFAULT_SERVER_HOST, port)
    }

    /// Build and start the server, defaulting to port 29275.
    /// 
    /// `host`: the host address for the server to listen on.
    /// 
    /// Returns a result containing a handle to the server, or the error variant if an error occurred while starting the server.
    pub fn start_default_port(&mut self, host: &'static str) -> io::Result<ServerHandle> {
        self.start(host, DEFAULT_PORT)
    }

    /// Build and start the server, defaulting to host "0.0.0.0" and port 29275.
    /// 
    /// Returns a result containing a handle to the server, or the error variant if an error occurred while starting the server.
    pub fn start_default(&mut self) -> io::Result<ServerHandle> {
        self.start(DEFAULT_SERVER_HOST, DEFAULT_PORT)
    }
}
