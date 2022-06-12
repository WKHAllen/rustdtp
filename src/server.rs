//! The server network interface.

use crate::util::*;
use serde::{de::DeserializeOwned, ser::Serialize};
use std::io;
use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

pub enum ServerEvent<R>
where
    R: DeserializeOwned,
{
    Connect { client_id: usize },
    Disconnect { client_id: usize },
    Receive { client_id: usize, data: R },
}

pub struct ServerHandle<S>
where
    S: Serialize, {}

impl<S> ServerHandle<S> where S: Serialize {}

pub struct Server<S, R>
where
    S: Serialize,
    R: DeserializeOwned, {}

impl<S, R> Server<S, R>
where
    S: Serialize,
    R: DeserializeOwned,
{
    pub async fn start<A>(addr: A) -> io::Result<(ServerHandle<S>, Receiver<ServerEvent<R>>)>
    where
        A: ToSocketAddrs,
    {
    }
}
