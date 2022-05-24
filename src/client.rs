//! The client network interface.

use crate::util::*;
use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// A command sent from the client handle to the client.
enum ClientCommand {
    Disconnect,
    Send { data: Vec<u8> },
    Connected,
    GetAddr,
    GetServerAddr,
}

/// The return value of a command executed on the client.
enum ClientCommandReturn {
    Disconnect(io::Result<()>),
    Send(io::Result<()>),
    Connected(bool),
    GetAddr(io::Result<SocketAddr>),
    GetServerAddr(io::Result<SocketAddr>),
}

/// The network client. Event callbacks must be provided via chaining:
/// 
/// ```no_run
/// use rustdtp::Client;
/// 
/// let client = Client::new()
///     .on_receive(|data| {
///         println!("Message from server: {:?}", data);
///     })
///     .on_disconnected(|| {
///         println!("Disconnected from server");
///     })
///     .connect_default()
///     .unwrap();
/// ```
#[derive(Debug)]
pub struct Client<R, D>
where
    R: Fn(&[u8]) + Clone + Send + 'static,
    D: Fn() + Clone + Send + 'static,
{
    on_receive: Option<R>,
    on_disconnected: Option<D>,
    connected: bool,
    shutdown: bool,
    cmd_receiver: mpsc::Receiver<ClientCommand>,
    cmd_return_sender: mpsc::Sender<ClientCommandReturn>,
}

impl<R, D> Client<R, D>
where
    R: Fn(&[u8]) + Clone + Send + 'static,
    D: Fn() + Clone + Send + 'static,
{
    /// Create a new client builder instance.
    pub fn new() -> ClientBuilder<R, D> {
        ClientBuilder::new()
    }

    /// Connect to a server.
    /// 
    /// `stream`: the client's TCP stream.
    /// 
    /// Returns a result of the error variant if an error occurred while connected to the server.
    pub fn connect(&mut self, stream: &mut TcpStream) -> io::Result<()> {
        if self.connected {
            return generic_error(*Error::AlreadyConnected);
        }

        self.connected = true;

        self.exchange_keys()?;
        self.handle(stream)
    }

    /// Perform client operations.
    /// 
    /// `stream`: the client's TCP stream.
    /// 
    /// Returns a result of the error variant if an error occurred while connected to the server.
    fn handle(&mut self, stream: &mut TcpStream) -> io::Result<()> {
        loop {
            if !self.connected {
                if !self.shutdown {
                    self.connected = true;
                    self.disconnect(&stream)?;
                }

                return Ok(());
            }

            let mut size_buffer = [0; LEN_SIZE];
            let result = match stream.read(&mut size_buffer) {
                Ok(size_len) => {
                    if size_len == 0 {
                        match &self.on_disconnected {
                            Some(on_disconnected) => on_disconnected(),
                            None => (),
                        }

                        self.disconnect(stream)?;

                        return Ok(());
                    }

                    assert_eq!(size_len, LEN_SIZE);

                    let msg_size = decode_message_size(&size_buffer);
                    let mut buffer = vec![0; msg_size];

                    match stream.read(&mut buffer) {
                        Ok(len) => {
                            assert_eq!(len, msg_size);

                            // TODO: decrypt data
                            let msg = buffer.as_slice();

                            match &self.on_receive {
                                Some(on_receive) => on_receive(msg),
                                None => (),
                            }

                            Ok(())
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            if self.connected {
                                Ok(())
                            } else {
                                generic_error(*Error::ClientDisconnected)
                            }
                        }
                        Err(e) => Err(e),
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if self.connected {
                        Ok(())
                    } else {
                        generic_error(*Error::ClientDisconnected)
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

            match self.cmd_receiver.recv_timeout(Duration::from_millis(10)) {
                Ok(cmd) => self.execute_command(cmd, stream),
                Err(_) => Ok(()),
            }?;
        }
    }

    fn exchange_keys(&mut self) -> io::Result<()> {
        // TODO: implement key exchange
        Ok(())
    }

    /// Disconnect from the server.
    /// 
    /// `stream`: the client's TCP stream.
    /// 
    /// Returns a result of the error variant if an error occurred while disconnecting from the server.
    pub fn disconnect(&mut self, stream: &TcpStream) -> io::Result<()> {
        if !self.connected {
            return generic_error(*Error::NotConnected);
        }

        stream.shutdown(Shutdown::Both)?;

        self.connected = false;
        self.shutdown = true;

        Ok(())
    }

    /// Send data to the server.
    /// 
    /// `stream`: the client's TCP stream.
    /// `data`: the data to send.
    /// 
    /// Returns a result of the error variant if an error occurred while sending data.
    pub fn send(&self, stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
        if !self.connected {
            return generic_error(*Error::NotConnected);
        }

        // TODO: encrypt data
        let size = encode_message_size(data.len());
        let mut buffer = vec![];
        buffer.extend_from_slice(&size);
        buffer.extend_from_slice(data);

        assert_eq!(buffer.len(), data.len() + LEN_SIZE);

        stream.write(&buffer)?;

        Ok(())
    }

    /// Check if the client is connected to a server.
    /// 
    /// Returns a boolean value representing whether the client is connected to a server.
    pub fn connected(&self) -> bool {
        self.connected
    }

    /// Get the address the client is connected on.
    /// 
    /// `stream`: the client's TCP stream.
    /// 
    /// Returns a result containing the address the client is connected on, or the error variant if the client is not connected.
    pub fn get_addr(&self, stream: &TcpStream) -> io::Result<SocketAddr> {
        if !self.connected {
            return generic_error(*Error::NotConnected);
        }

        stream.local_addr()
    }

    /// Get the address of the server.
    /// 
    /// `stream`: the client's TCP stream.
    /// 
    /// Returns a result containing the address of the server, or the error variant if the client is not connected.
    pub fn get_server_addr(&self, stream: &TcpStream) -> io::Result<SocketAddr> {
        if !self.connected {
            return generic_error(*Error::NotConnected);
        }

        stream.peer_addr()
    }

    /// Execute a command from the client handle.
    /// 
    /// `command`: the command to execute.
    /// `stream`: the client's TCP stream.
    /// 
    /// Returns a result of the error variant if an error occurred while executing the command.
    fn execute_command(
        &mut self,
        command: ClientCommand,
        stream: &mut TcpStream,
    ) -> io::Result<()> {
        match match command {
            ClientCommand::Disconnect => {
                let ret = self.disconnect(&stream);
                self.cmd_return_sender
                    .send(ClientCommandReturn::Disconnect(ret))
            }
            ClientCommand::Send { data } => self.cmd_return_sender.send(ClientCommandReturn::Send(
                self.send(stream, data.as_slice()),
            )),
            ClientCommand::Connected => self
                .cmd_return_sender
                .send(ClientCommandReturn::Connected(self.connected())),
            ClientCommand::GetAddr => self
                .cmd_return_sender
                .send(ClientCommandReturn::GetAddr(self.get_addr(&stream))),
            ClientCommand::GetServerAddr => {
                self.cmd_return_sender
                    .send(ClientCommandReturn::GetServerAddr(
                        self.get_server_addr(&stream),
                    ))
            }
        } {
            Ok(()) => Ok(()),
            Err(err) => generic_error(err),
        }
    }
}

impl<R, D> Drop for Client<R, D>
where
    R: Fn(&[u8]) + Clone + Send + 'static,
    D: Fn() + Clone + Send + 'static,
{
    /// Disconnect the client from the server and wait for it to fully shut down before dropping it.
    fn drop(&mut self) {
        self.connected = false;

        while !self.shutdown {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// A handle to a running client.
#[derive(Debug)]
pub struct ClientHandle {
    cmd_sender: mpsc::Sender<ClientCommand>,
    cmd_return_receiver: mpsc::Receiver<ClientCommandReturn>,
}

impl ClientHandle {
    /// Disconnect from the server.
    /// 
    /// Returns a result of the error variant if an error occurred while disconnecting from the server.
    pub fn disconnect(&self) -> io::Result<()> {
        match self.cmd_sender.send(ClientCommand::Disconnect) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ClientCommandReturn::Disconnect(value) => value,
                    _ => generic_error(*Error::ChannelWrongResponse),
                },
                Err(_) => generic_error(*Error::NotConnected),
            },
            Err(_) => generic_error(*Error::NotConnected),
        }
    }

    /// Send data to the server.
    /// 
    /// `data`: the data to send.
    /// 
    /// Returns a result of the error variant if an error occurred while sending data.
    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        match self.cmd_sender.send(ClientCommand::Send {
            data: data.to_vec(),
        }) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ClientCommandReturn::Send(value) => value,
                    _ => generic_error(*Error::ChannelWrongResponse),
                },
                Err(_) => generic_error(*Error::NotConnected),
            },
            Err(_) => generic_error(*Error::NotConnected),
        }
    }

    /// Check if the client is connected to a server.
    /// 
    /// Returns a result containing a boolean value representing whether the client is connected to a server, or the error variant if a channel error occurred.
    pub fn connected(&self) -> io::Result<bool> {
        match self.cmd_sender.send(ClientCommand::Connected) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ClientCommandReturn::Connected(value) => Ok(value),
                    _ => generic_error(*Error::ChannelWrongResponse),
                },
                Err(_) => Ok(false),
            },
            Err(_) => Ok(false),
        }
    }

    /// Get the address the client is connected on.
    /// 
    /// Returns a result containing the address the client is connected on, or the error variant if the client is not connected.
    pub fn get_addr(&self) -> io::Result<SocketAddr> {
        match self.cmd_sender.send(ClientCommand::GetAddr) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ClientCommandReturn::GetAddr(value) => value,
                    _ => generic_error(*Error::ChannelWrongResponse),
                },
                Err(_) => generic_error(*Error::NotConnected),
            },
            Err(_) => generic_error(*Error::NotConnected),
        }
    }

    /// Get the address of the server.
    /// 
    /// Returns a result containing the address of the server, or the error variant if the client is not connected.
    pub fn get_server_addr(&self) -> io::Result<SocketAddr> {
        match self.cmd_sender.send(ClientCommand::GetServerAddr) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ClientCommandReturn::GetServerAddr(value) => value,
                    _ => generic_error(*Error::ChannelWrongResponse),
                },
                Err(_) => generic_error(*Error::NotConnected),
            },
            Err(_) => generic_error(*Error::NotConnected),
        }
    }
}

impl Drop for ClientHandle {
    /// Disconnect the client from the server and wait for it to fully shut down before dropping the handle to it.
    fn drop(&mut self) {
        if self.connected().unwrap() {
            self.disconnect().unwrap();
        }
    }
}

/// A client builder. The event callback methods must all be chained before the client can be built. The `connect` methods build the client and connect it to a server.
#[derive(Debug)]
pub struct ClientBuilder<R, D>
where
    R: Fn(&[u8]) + Clone + Send + 'static,
    D: Fn() + Clone + Send + 'static,
{
    on_receive: Option<R>,
    on_disconnected: Option<D>,
}

impl<R, D> ClientBuilder<R, D>
where
    R: Fn(&[u8]) + Clone + Send + 'static,
    D: Fn() + Clone + Send + 'static,
{
    /// Create a new client builder instance.
    pub fn new() -> Self {
        Self {
            on_receive: None,
            on_disconnected: None,
        }
    }

    /// Register the receive event callback.
    /// 
    /// `on_receive`: called when the client receives data from the server.
    pub fn on_receive(&mut self, on_receive: R) -> &mut Self {
        self.on_receive = Some(on_receive);
        self
    }

    /// Register the disconnected event callback.
    /// 
    /// `on_disconnected`: called when a client has been disconnected from the server.
    pub fn on_disconnected(&mut self, on_disconnected: D) -> &mut Self {
        self.on_disconnected = Some(on_disconnected);
        self
    }

    /// Build the client and connect to a server.
    /// 
    /// `host`: the host address of the server to connect to.
    /// `port`: the port of the server to connect to.
    /// 
    /// Returns a result containing a handle to the client, or the error variant if an error occurred while connecting to the server.
    pub fn connect(&mut self, host: &str, port: u16) -> io::Result<ClientHandle> {
        let (cmd_sender, cmd_receiver) = mpsc::channel();
        let (cmd_return_sender, cmd_return_receiver) = mpsc::channel();

        let addr = format!("{}:{}", host, port);
        let mut stream = TcpStream::connect(addr)?;
        stream.set_nonblocking(true)?;

        let mut client = Client {
            on_receive: self.on_receive.clone(),
            on_disconnected: self.on_disconnected.clone(),
            connected: false,
            shutdown: false,
            cmd_receiver,
            cmd_return_sender,
        };

        thread::spawn(move || {
            client.connect(&mut stream).unwrap();
        });

        Ok(ClientHandle {
            cmd_sender,
            cmd_return_receiver,
        })
    }

    /// Build the client and connect to a server, defaulting to host "127.0.0.1".
    /// 
    /// `port`: the port of the server to connect to.
    /// 
    /// Returns a result containing a handle to the client, or the error variant if an error occurred while connecting to the server.
    pub fn connect_default_host(&mut self, port: u16) -> io::Result<ClientHandle> {
        self.connect(DEFAULT_CLIENT_HOST, port)
    }

    /// Build the client and connect to a server, defaulting to port 29275.
    /// 
    /// `host`: the host address of the server to connect to.
    /// 
    /// Returns a result containing a handle to the client, or the error variant if an error occurred while connecting to the server.
    pub fn connect_default_port(&mut self, host: &str) -> io::Result<ClientHandle> {
        self.connect(host, DEFAULT_PORT)
    }

    /// Build the client and connect to a server, defaulting to host "127.0.0.1" and port 29275.
    /// 
    /// Returns a result containing a handle to the client, or the error variant if an error occurred while connecting to the server.
    pub fn connect_default(&mut self) -> io::Result<ClientHandle> {
        self.connect(DEFAULT_CLIENT_HOST, DEFAULT_PORT)
    }
}
