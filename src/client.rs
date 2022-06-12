//! The client network interface.

use crate::util::*;
use serde::{de::DeserializeOwned, ser::Serialize};
use std::io;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};

pub enum ClientEvent<R>
where
    R: DeserializeOwned,
{
    Disconnected,
    Receive { data: R },
}

pub struct ClientHandle<S>
where
    S: Serialize, {}

impl<S> ClientHandle<S> where S: Serialize {}

pub struct Client<S, R>
where
    S: Serialize,
    R: DeserializeOwned, {}

impl<S, R> Client<S, R>
where
    S: Serialize,
    R: DeserializeOwned,
{
    pub async fn connect<A>(addr: A) -> io::Result<(ClientHandle<S>, Receiver<ClientEvent<R>>)>
    where
        A: ToSocketAddrs,
    {
    }
}
