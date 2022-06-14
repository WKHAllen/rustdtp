//! The client network interface.

use super::command_channel::*;
use super::util::*;
use serde::{de::DeserializeOwned, ser::Serialize};
use std::io;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::mpsc::{channel, Receiver, Sender};
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

pub enum ClientEvent<R>
where
    R: DeserializeOwned + Send + 'static,
{
    Disconnected,
    Receive { data: R },
}

pub struct ClientHandle<S>
where
    S: Serialize + Send + 'static,
{
    client_command_sender: CommandChannelSender<ClientCommand<S>, ClientCommandReturn>,
    client_task_handle: JoinHandle<()>,
}

impl<S> ClientHandle<S>
where
    S: Serialize + Send + 'static,
{
    pub async fn disconnect(mut self) -> io::Result<()> {
        let value = self
            .client_command_sender
            .send(ClientCommand::Disconnect)
            .await?;
        self.client_task_handle.await.unwrap();
        unwrap_enum!(value, ClientCommandReturn::Disconnect)
    }

    pub async fn send(&mut self, data: S) -> io::Result<()> {
        let value = self
            .client_command_sender
            .send(ClientCommand::Send { data })
            .await?;
        unwrap_enum!(value, ClientCommandReturn::Send)
    }

    pub async fn get_addr(&mut self) -> io::Result<SocketAddr> {
        let value = self
            .client_command_sender
            .send(ClientCommand::GetAddr)
            .await?;
        unwrap_enum!(value, ClientCommandReturn::GetAddr)
    }

    pub async fn get_server_addr(&mut self) -> io::Result<SocketAddr> {
        let value = self
            .client_command_sender
            .send(ClientCommand::GetServerAddr)
            .await?;
        unwrap_enum!(value, ClientCommandReturn::GetServerAddr)
    }
}

pub struct Client<S, R>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    phantom_send: std::marker::PhantomData<S>,
    phantom_receive: std::marker::PhantomData<R>,
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
        // TODO: implement
        todo!();
    }
}
