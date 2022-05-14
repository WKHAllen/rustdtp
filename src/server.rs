use crate::util::*;
use std::collections::HashMap;
use std::io;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

enum ServerCommand {
    Stop,
    Send { data: Vec<u8>, client_id: usize },
    SendAll { data: Vec<u8> },
    Serving,
    GetAddr,
    GetClientAddr { client_id: usize },
    RemoveClient { client_id: usize },
}

enum ServerCommandReturn {
    Stop(io::Result<()>),
    Send(io::Result<()>),
    SendAll(io::Result<()>),
    Serving(bool),
    GetAddr(io::Result<SocketAddr>),
    GetClientAddr(io::Result<SocketAddr>),
    RemoveClient(io::Result<()>),
}

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
    pub fn new() -> ServerBuilder<R, C, D> {
        ServerBuilder::new()
    }

    pub fn start(&mut self, listener: TcpListener) -> io::Result<()> {
        if self.serving {
            return Err(io::Error::new(io::ErrorKind::Other, "Already serving"));
        }

        self.serving = true;

        self.serve(listener)
    }

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

                    self.exchange_keys(client_id, &conn)?;
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

    fn exchange_keys(&self, _client_id: usize, _client: &TcpStream) -> io::Result<()> {
        // TODO: implement key exchange
        Ok(())
    }

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

                                // TODO: decrypt data
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
                                    Err(io::Error::new(io::ErrorKind::Other, "Done"))
                                }
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        if self.serving {
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
                        return Ok(true);
                    } else {
                        return Err(result_err);
                    }
                }

                Ok(true)
            }
            None => Err(io::Error::new(io::ErrorKind::NotFound, "Invalid client ID")),
        }
    }

    fn serve_clients(&self) -> io::Result<Vec<usize>> {
        let mut clients_to_remove = vec![];

        for (client_id, _) in &self.clients {
            if !self.serve_client(*client_id)? {
                clients_to_remove.push(*client_id);
            };
        }

        Ok(clients_to_remove)
    }

    pub fn stop(&mut self) -> io::Result<()> {
        if !self.serving {
            return Err(io::Error::new(io::ErrorKind::Other, "Not serving"));
        }

        self.serving = false;

        for (_, client) in &self.clients {
            client.shutdown(Shutdown::Both)?;
        }

        self.clients.clear();

        self.shutdown = true;

        Ok(())
    }

    pub fn send(&self, data: &[u8], client_id: usize) -> io::Result<()> {
        if !self.serving {
            return Err(io::Error::new(io::ErrorKind::Other, "Not serving"));
        }

        match self.clients.get(&client_id) {
            Some(mut client) => {
                // TODO: encrypt data
                let size = encode_message_size(data.len());
                let mut buffer = vec![];
                buffer.extend_from_slice(&size);
                buffer.extend_from_slice(data);

                assert_eq!(buffer.len(), data.len() + LEN_SIZE);

                client.write(&buffer)?;
                Ok(())
            }
            None => Err(io::Error::new(io::ErrorKind::NotFound, "Invalid client ID")),
        }
    }

    pub fn send_all(&self, data: &[u8]) -> io::Result<()> {
        for (client_id, _) in &self.clients {
            self.send(data, *client_id)?;
        }

        Ok(())
    }

    pub fn serving(&self) -> bool {
        self.serving
    }

    pub fn get_addr(&self, listener: &TcpListener) -> io::Result<SocketAddr> {
        if !self.serving {
            return Err(io::Error::new(io::ErrorKind::Other, "Not serving"));
        }

        listener.local_addr()
    }

    pub fn get_client_addr(&self, client_id: usize) -> io::Result<SocketAddr> {
        if !self.serving {
            return Err(io::Error::new(io::ErrorKind::Other, "Not serving"));
        }

        match self.clients.get(&client_id) {
            Some(client) => client.peer_addr(),
            None => Err(io::Error::new(io::ErrorKind::NotFound, "Invalid client ID")),
        }
    }

    pub fn remove_client(&mut self, client_id: usize) -> io::Result<()> {
        if !self.serving {
            return Err(io::Error::new(io::ErrorKind::Other, "Not serving"));
        }

        match self.clients.get(&client_id) {
            Some(client) => {
                client.shutdown(Shutdown::Both)?;
                self.clients.remove(&client_id);
                // TODO: remove client's key
                Ok(())
            }
            None => Err(io::Error::new(io::ErrorKind::NotFound, "Invalid client ID")),
        }
    }

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
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, err)),
        }
    }
}

impl<R, C, D> Drop for Server<R, C, D>
where
    R: Fn(usize, &[u8]) + Clone + Send + 'static,
    C: Fn(usize) + Clone + Send + 'static,
    D: Fn(usize) + Clone + Send + 'static,
{
    fn drop(&mut self) {
        self.serving = false;

        while !self.shutdown {
            thread::sleep(Duration::from_millis(10));
        }
    }
}

pub struct ServerHandle {
    cmd_sender: mpsc::Sender<ServerCommand>,
    cmd_return_receiver: mpsc::Receiver<ServerCommandReturn>,
}

impl ServerHandle {
    pub fn stop(&self) -> io::Result<()> {
        match self.cmd_sender.send(ServerCommand::Stop) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ServerCommandReturn::Stop(value) => value,
                    _ => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Incorrect return value from command channel",
                    )),
                },
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not serving")),
            },
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not serving")),
        }
    }

    pub fn send(&self, data: &[u8], client_id: usize) -> io::Result<()> {
        match self.cmd_sender.send(ServerCommand::Send {
            data: data.to_vec(),
            client_id,
        }) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ServerCommandReturn::Send(value) => value,
                    _ => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Incorrect return value from command channel",
                    )),
                },
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not serving")),
            },
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not serving")),
        }
    }

    pub fn send_all(&self, data: &[u8]) -> io::Result<()> {
        match self.cmd_sender.send(ServerCommand::SendAll {
            data: data.to_vec(),
        }) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ServerCommandReturn::SendAll(value) => value,
                    _ => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Incorrect return value from command channel",
                    )),
                },
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not serving")),
            },
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not serving")),
        }
    }

    pub fn serving(&self) -> io::Result<bool> {
        match self.cmd_sender.send(ServerCommand::Serving) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ServerCommandReturn::Serving(value) => Ok(value),
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
        match self.cmd_sender.send(ServerCommand::GetAddr) {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ServerCommandReturn::GetAddr(value) => value,
                    _ => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Incorrect return value from command channel",
                    )),
                },
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not serving")),
            },
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not serving")),
        }
    }

    pub fn get_client_addr(&self, client_id: usize) -> io::Result<SocketAddr> {
        match self
            .cmd_sender
            .send(ServerCommand::GetClientAddr { client_id })
        {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ServerCommandReturn::GetClientAddr(value) => value,
                    _ => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Incorrect return value from command channel",
                    )),
                },
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not serving")),
            },
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not serving")),
        }
    }

    pub fn remove_client(&self, client_id: usize) -> io::Result<()> {
        match self
            .cmd_sender
            .send(ServerCommand::RemoveClient { client_id })
        {
            Ok(()) => match self.cmd_return_receiver.recv() {
                Ok(received) => match received {
                    ServerCommandReturn::RemoveClient(value) => value,
                    _ => Err(io::Error::new(
                        io::ErrorKind::Other,
                        "Incorrect return value from command channel",
                    )),
                },
                Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not serving")),
            },
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Not serving")),
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        if self.serving().unwrap() {
            self.stop().unwrap();
        }
    }
}

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
    pub fn new() -> Self {
        Self {
            on_receive: None,
            on_connect: None,
            on_disconnect: None,
        }
    }

    pub fn on_receive(&mut self, on_receive: R) -> &mut Self {
        self.on_receive = Some(on_receive);
        self
    }

    pub fn on_connect(&mut self, on_connect: C) -> &mut Self {
        self.on_connect = Some(on_connect);
        self
    }

    pub fn on_disconnect(&mut self, on_disconnect: D) -> &mut Self {
        self.on_disconnect = Some(on_disconnect);
        self
    }

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

    pub fn start_default_host(&mut self, port: u16) -> io::Result<ServerHandle> {
        self.start(DEFAULT_SERVER_HOST, port)
    }

    pub fn start_default_port(&mut self, host: &'static str) -> io::Result<ServerHandle> {
        self.start(host, DEFAULT_PORT)
    }

    pub fn start_default(&mut self) -> io::Result<ServerHandle> {
        self.start(DEFAULT_SERVER_HOST, DEFAULT_PORT)
    }
}
