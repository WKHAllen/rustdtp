use crate::util::*;
use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

enum ClientCommand {
    Disconnect,
    Send { data: Vec<u8> },
    Connected,
    GetAddr,
    GetServerAddr,
}

enum ClientCommandReturn {
    Disconnect(io::Result<()>),
    Send(io::Result<()>),
    Connected(bool),
    GetAddr(io::Result<SocketAddr>),
    GetServerAddr(io::Result<SocketAddr>),
}

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
    pub fn new() -> ClientBuilder<R, D> {
        ClientBuilder::new()
    }

    pub fn connect(&mut self, stream: &mut TcpStream) -> io::Result<()> {
        if self.connected {
            return Err(io::Error::new(io::ErrorKind::Other, "Already connected"));
        }

        self.connected = true;

        self.exchange_keys()?;
        self.handle(stream)
    }

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
                                Err(io::Error::new(io::ErrorKind::Other, "Done"))
                            }
                        }
                        Err(e) => Err(e),
                    }
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if self.connected {
                        Ok(())
                    } else {
                        Err(io::Error::new(io::ErrorKind::Other, "Done"))
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

    pub fn disconnect(&mut self, stream: &TcpStream) -> io::Result<()> {
        if !self.connected {
            return Err(io::Error::new(io::ErrorKind::Other, "Not connected"));
        }

        stream.shutdown(Shutdown::Both)?;

        self.connected = false;
        self.shutdown = true;

        Ok(())
    }

    pub fn send(&self, stream: &mut TcpStream, data: &[u8]) -> io::Result<()> {
        if !self.connected {
            return Err(io::Error::new(io::ErrorKind::Other, "Not connected"));
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

    pub fn connected(&self) -> bool {
        self.connected
    }

    pub fn get_addr(&self, stream: &TcpStream) -> io::Result<SocketAddr> {
        if !self.connected {
            return Err(io::Error::new(io::ErrorKind::Other, "Not connected"));
        }

        stream.local_addr()
    }

    pub fn get_server_addr(&self, stream: &TcpStream) -> io::Result<SocketAddr> {
        if !self.connected {
            return Err(io::Error::new(io::ErrorKind::Other, "Not connected"));
        }

        stream.peer_addr()
    }

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
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, err)),
        }
    }
}

impl<R, D> Drop for Client<R, D>
where
    R: Fn(&[u8]) + Clone + Send + 'static,
    D: Fn() + Clone + Send + 'static,
{
    fn drop(&mut self) {
        self.connected = false;

        while !self.shutdown {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

#[derive(Debug)]
pub struct ClientHandle {
    cmd_sender: mpsc::Sender<ClientCommand>,
    cmd_return_receiver: mpsc::Receiver<ClientCommandReturn>,
}

impl ClientHandle {
    pub fn disconnect(&self) -> io::Result<()> {
        match self.cmd_sender.send(ClientCommand::Disconnect) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ClientCommandReturn::Disconnect(value) => value,
                    _ => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Incorrect return value from command channel",
                    )),
                },
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not connected")),
            },
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not connected")),
        }
    }

    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        match self.cmd_sender.send(ClientCommand::Send {
            data: data.to_vec(),
        }) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ClientCommandReturn::Send(value) => value,
                    _ => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Incorrect return value from command channel",
                    )),
                },
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not connected")),
            },
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not connected")),
        }
    }

    pub fn connected(&self) -> io::Result<bool> {
        match self.cmd_sender.send(ClientCommand::Connected) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ClientCommandReturn::Connected(value) => Ok(value),
                    _ => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Incorrect return value from command channel",
                    )),
                },
                Err(_) => Ok(false),
            },
            Err(_) => Ok(false),
        }
    }

    pub fn get_addr(&self) -> io::Result<SocketAddr> {
        match self.cmd_sender.send(ClientCommand::GetAddr) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ClientCommandReturn::GetAddr(value) => value,
                    _ => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Incorrect return value from command channel",
                    )),
                },
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not connected")),
            },
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not connected")),
        }
    }

    pub fn get_server_addr(&self) -> io::Result<SocketAddr> {
        match self.cmd_sender.send(ClientCommand::GetServerAddr) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ClientCommandReturn::GetServerAddr(value) => value,
                    _ => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Incorrect return value from command channel",
                    )),
                },
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not connected")),
            },
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not connected")),
        }
    }
}

impl Drop for ClientHandle {
    fn drop(&mut self) {
        if self.connected().unwrap() {
            self.disconnect().unwrap();
        }
    }
}

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
    pub fn new() -> Self {
        Self {
            on_receive: None,
            on_disconnected: None,
        }
    }

    pub fn on_receive(&mut self, on_receive: R) -> &mut Self {
        self.on_receive = Some(on_receive);
        self
    }

    pub fn on_disconnected(&mut self, on_disconnected: D) -> &mut Self {
        self.on_disconnected = Some(on_disconnected);
        self
    }

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

    pub fn connect_default_host(&mut self, port: u16) -> io::Result<ClientHandle> {
        self.connect(DEFAULT_CLIENT_HOST, port)
    }

    pub fn connect_default_port(&mut self, host: &str) -> io::Result<ClientHandle> {
        self.connect(host, DEFAULT_PORT)
    }

    pub fn connect_default(&mut self) -> io::Result<ClientHandle> {
        self.connect(DEFAULT_CLIENT_HOST, DEFAULT_PORT)
    }
}
