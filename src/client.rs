//! The client network interface.

use super::util::*;
use serde::{de::DeserializeOwned, ser::Serialize};
use std::io;
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
    client_command_sender: Sender<ClientCommand<S>>,
    client_task_handle: JoinHandle<()>,
}

impl<S> ClientHandle<S>
where
    S: Serialize + Send + 'static,
{
    pub async fn disconnect(self) -> io::Result<()> {
        // TODO: implement
        todo!();
        self.client_task_handle.await.unwrap();
    }

    pub async fn send(&self, data: S) -> io::Result<()> {
        // TODO: implement
        todo!();
    }

    pub async fn get_addr(&self) -> io::Result<()> {
        // TODO: implement
        todo!();
    }

    pub async fn get_server_addr(&self) -> io::Result<()> {
        // TODO: implement
        todo!();
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
        todo!();
    }
}
