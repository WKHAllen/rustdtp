//! Protocol server implementation.

use super::command_channel::*;
use super::event_stream::*;
use super::timeout::*;
use crate::crypto::*;
use crate::util::*;
use async_trait::async_trait;
use rsa::pkcs8::EncodePublicKey;
use serde::{de::DeserializeOwned, ser::Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::mpsc::{channel, Sender};
use tokio::task::JoinHandle;

/// Configuration for a server's event callbacks.
///
/// # Events
///
/// There are four events for which callbacks can be registered:
///
///  - `connect`
///  - `disconnect`
///  - `receive`
///  - `stop`
///
/// All callbacks are optional, and can be registered for any combination of
/// these events. Note that each callback must be provided as a function or
/// closure returning a heap-allocated, thread-safe future. The future will be
/// awaited by the runtime.
///
/// # Example
///
/// ```no_run
/// # use rustdtp::*;
///
/// # #[tokio::main]
/// # async fn main() {
/// let server = Server::builder()
///     .sending::<usize>()
///     .receiving::<String>()
///     .with_event_callbacks(
///         ServerEventCallbacks::new()
///             .on_connect(move |client_id| {
///                 Box::pin(async move {
///                     // some async operation...
///                     println!("Client with ID {} connected", client_id);
///                 })
///             })
///             .on_disconnect(move |client_id| {
///                 Box::pin(async move {
///                     // some async operation...
///                     println!("Client with ID {} disconnected", client_id);
///                 })
///             })
///             .on_receive(move |client_id, data| {
///                 Box::pin(async move {
///                     // some async operation...
///                     println!("Received data from client with ID {}: {}", client_id, data);
///                 })
///             })
///             .on_stop(move || {
///                 Box::pin(async move {
///                     // some async operation...
///                     println!("Server closed");
///                 })
///             })
///     )
///     .start(("0.0.0.0", 0))
///     .await
///     .unwrap();
/// # }
/// ```
#[allow(clippy::type_complexity)]
pub struct ServerEventCallbacks<R>
where
    R: DeserializeOwned + Send + 'static,
{
    /// The `connect` event callback.
    connect: Option<Box<dyn Fn(usize) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>>,
    /// The `disconnect` event callback.
    disconnect: Option<Box<dyn Fn(usize) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>>,
    /// The `receive` event callback.
    receive: Option<Box<dyn Fn(usize, R) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>>,
    /// The `stop` event callback.
    stop: Option<Box<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>>,
}

impl<R> ServerEventCallbacks<R>
where
    R: DeserializeOwned + Send + 'static,
{
    /// Creates a new server event callbacks configuration with all callbacks
    /// empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a callback on the `connect` event.
    pub fn on_connect<F>(mut self, callback: F) -> Self
    where
        F: Fn(usize) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
    {
        self.connect = Some(Box::new(callback));
        self
    }

    /// Registers a callback on the `disconnect` event.
    pub fn on_disconnect<F>(mut self, callback: F) -> Self
    where
        F: Fn(usize) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
    {
        self.disconnect = Some(Box::new(callback));
        self
    }

    /// Registers a callback on the `receive` event.
    pub fn on_receive<F>(mut self, callback: F) -> Self
    where
        F: Fn(usize, R) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
    {
        self.receive = Some(Box::new(callback));
        self
    }

    /// Registers a callback on the `stop` event.
    pub fn on_stop<F>(mut self, callback: F) -> Self
    where
        F: Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + 'static,
    {
        self.stop = Some(Box::new(callback));
        self
    }
}

impl<R> Default for ServerEventCallbacks<R>
where
    R: DeserializeOwned + Send + 'static,
{
    fn default() -> Self {
        Self {
            connect: None,
            disconnect: None,
            receive: None,
            stop: None,
        }
    }
}

/// An event handling trait for the server.
///
/// # Events
///
/// There are four events for which methods can be implemented:
///
///  - `connect`
///  - `disconnect`
///  - `receive`
///  - `stop`
///
/// All method implementations are optional, and can be registered for any
/// combination of these events. Note that the type that implements the trait
/// must be `Send + Sync`, and that the trait implementation must apply the
/// `async_trait` macro.
///
/// # Example
///
/// ```no_run
/// # use rustdtp::*;
///
/// # #[tokio::main]
/// # async fn main() {
/// struct MyServerHandler;
///
/// #[async_trait]
/// impl ServerEventHandler<String> for MyServerHandler {
///     async fn on_connect(&self, client_id: usize) {
///         // some async operation...
///         println!("Client with ID {} connected", client_id);
///     }
///
///     async fn on_disconnect(&self, client_id: usize) {
///         // some async operation...
///         println!("Client with ID {} disconnected", client_id);
///     }
///
///     async fn on_receive(&self, client_id: usize, data: String) {
///         // some async operation...
///         println!("Received data from client with ID {}: {}", client_id, data);
///     }
///
///     async fn on_stop(&self) {
///         // some async operation...
///         println!("Server closed");
///     }
/// }
///
/// let server = Server::builder()
///     .sending::<usize>()
///     .receiving::<String>()
///     .with_event_handler(MyServerHandler)
///     .start(("0.0.0.0", 0))
///     .await
///     .unwrap();
/// # }
/// ```
#[async_trait]
pub trait ServerEventHandler<R>
where
    Self: Send + Sync,
    R: DeserializeOwned + Send + 'static,
{
    /// Handles the `connect` event.
    #[allow(unused_variables)]
    async fn on_connect(&self, client_id: usize) {}

    /// Handles the `disconnect` event.
    #[allow(unused_variables)]
    async fn on_disconnect(&self, client_id: usize) {}

    /// Handles the `receive` event.
    #[allow(unused_variables)]
    async fn on_receive(&self, client_id: usize, data: R) {}

    /// Handles the `stop` event.
    async fn on_stop(&self) {}
}

/// Unknown server sending type.
pub struct ServerSendingUnknown;

/// Known server sending type, stored as the type parameter `S`.
pub struct ServerSending<S>(PhantomData<S>)
where
    S: Serialize + Send + 'static;

/// A server sending marker trait.
pub(crate) trait ServerSendingConfig {}

impl ServerSendingConfig for ServerSendingUnknown {}

impl<S> ServerSendingConfig for ServerSending<S> where S: Serialize + Send + 'static {}

/// Unknown server receiving type.
pub struct ServerReceivingUnknown;

/// Known server receiving type, stored as the type parameter `R`.
pub struct ServerReceiving<R>(PhantomData<R>)
where
    R: DeserializeOwned + Send + 'static;

/// A server receiving marker trait.
pub(crate) trait ServerReceivingConfig {}

impl ServerReceivingConfig for ServerReceivingUnknown {}

impl<R> ServerReceivingConfig for ServerReceiving<R> where R: DeserializeOwned + Send + 'static {}

/// Unknown server event reporting type.
pub struct ServerEventReportingUnknown;

/// Known server event reporting type, stored as the type parameter `E`.
pub struct ServerEventReporting<E>(E);

/// Server event reporting via callbacks.
pub struct ServerEventReportingCallbacks<R>(ServerEventCallbacks<R>)
where
    R: DeserializeOwned + Send + 'static;

/// Server event reporting via an event handler.
pub struct ServerEventReportingHandler<R, H>
where
    R: DeserializeOwned + Send + 'static,
    H: ServerEventHandler<R>,
{
    /// The event handler instance.
    handler: H,
    /// Phantom `R` owner.
    phantom_receive: PhantomData<R>,
}

/// Server event reporting via a channel.
pub struct ServerEventReportingChannel;

/// A server event reporting marker trait.
pub(crate) trait ServerEventReportingConfig {}

impl ServerEventReportingConfig for ServerEventReportingUnknown {}

impl<R> ServerEventReportingConfig for ServerEventReporting<ServerEventReportingCallbacks<R>> where
    R: DeserializeOwned + Send + 'static
{
}

impl<R, H> ServerEventReportingConfig for ServerEventReporting<ServerEventReportingHandler<R, H>>
where
    R: DeserializeOwned + Send + 'static,
    H: ServerEventHandler<R>,
{
}

impl ServerEventReportingConfig for ServerEventReporting<ServerEventReportingChannel> {}

/// A builder for the [`Server`].
///
/// An instance of this can be constructed using `ServerBuilder::new()` or
/// `Server::builder()`. The configuration information exists primarily at the
/// type-level, so it is impossible to misconfigure this.
///
/// This method of configuration is technically not necessary, but it is far
/// clearer and more explicit than simply configuring the `Server` type. Plus,
/// it provides additional ways of detecting events.
///
/// # Configuration
///
/// To configure the server, first provide the types that will be sent and
/// received through the server using the `.sending::<...>()` and
/// `.receiving::<...>()` methods. Then specify the way in which events will
/// be detected. There are three methods of receiving events:
///
/// - via callback functions (`.with_event_callbacks(...)`)
/// - via implementation of a handler trait (`.with_event_handler(...)`)
/// - via a channel (`.with_event_channel()`)
///
/// The channel method is the most versatile, hence why it's the `Server`'s
/// default implementation. The other methods are provided to support a
/// greater variety of program architectures.
///
/// Once configured, the `.start(...)` method, which is effectively identical
/// to the `Server::start(...)` method, can be called to start the server.
///
/// # Example
///
/// ```no_run
/// # use rustdtp::*;
///
/// # #[tokio::main]
/// # async fn main() {
/// let (server, server_events) = Server::builder()
///     .sending::<usize>()
///     .receiving::<String>()
///     .with_event_channel()
///     .start(("0.0.0.0", 0))
///     .await
///     .unwrap();
/// # }
/// ```
#[allow(private_bounds)]
pub struct ServerBuilder<SC, RC, EC>
where
    SC: ServerSendingConfig,
    RC: ServerReceivingConfig,
    EC: ServerEventReportingConfig,
{
    /// Phantom `SC` owner.
    phantom_send: PhantomData<SC>,
    /// Phantom `RC` owner.
    phantom_receive: PhantomData<RC>,
    /// The event reporting configuration.
    event_reporting: EC,
}

impl ServerBuilder<ServerSendingUnknown, ServerReceivingUnknown, ServerEventReportingUnknown> {
    /// Creates a new server builder.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default
    for ServerBuilder<ServerSendingUnknown, ServerReceivingUnknown, ServerEventReportingUnknown>
{
    fn default() -> Self {
        ServerBuilder {
            phantom_send: PhantomData,
            phantom_receive: PhantomData,
            event_reporting: ServerEventReportingUnknown,
        }
    }
}

#[allow(private_bounds)]
impl<RC, EC> ServerBuilder<ServerSendingUnknown, RC, EC>
where
    RC: ServerReceivingConfig,
    EC: ServerEventReportingConfig,
{
    /// Configures the type of data the server intends to send to clients.
    pub fn sending<S>(self) -> ServerBuilder<ServerSending<S>, RC, EC>
    where
        S: Serialize + Send + 'static,
    {
        ServerBuilder {
            phantom_send: PhantomData,
            phantom_receive: PhantomData,
            event_reporting: self.event_reporting,
        }
    }
}

#[allow(private_bounds)]
impl<SC, EC> ServerBuilder<SC, ServerReceivingUnknown, EC>
where
    SC: ServerSendingConfig,
    EC: ServerEventReportingConfig,
{
    /// Configures the type of data the server intends to receive from
    /// clients.
    pub fn receiving<R>(self) -> ServerBuilder<SC, ServerReceiving<R>, EC>
    where
        R: DeserializeOwned + Send + 'static,
    {
        ServerBuilder {
            phantom_send: PhantomData,
            phantom_receive: PhantomData,
            event_reporting: self.event_reporting,
        }
    }
}

#[allow(private_bounds)]
impl<S, R> ServerBuilder<ServerSending<S>, ServerReceiving<R>, ServerEventReportingUnknown>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    /// Configures the server to receive events via callbacks.
    ///
    /// Using callbacks is typically considered an anti-pattern in Rust, so
    /// this should only be used if it makes sense in the context of the
    /// design of the code utilizing this API.
    ///
    /// See [`ServerEventCallbacks`] for more information and examples.
    pub fn with_event_callbacks(
        self,
        callbacks: ServerEventCallbacks<R>,
    ) -> ServerBuilder<
        ServerSending<S>,
        ServerReceiving<R>,
        ServerEventReporting<ServerEventReportingCallbacks<R>>,
    >
    where
        R: DeserializeOwned + Send + 'static,
    {
        ServerBuilder {
            phantom_send: PhantomData,
            phantom_receive: PhantomData,
            event_reporting: ServerEventReporting(ServerEventReportingCallbacks(callbacks)),
        }
    }

    /// Configures the server to receive events via a trait implementation.
    ///
    /// This provides an approach to event handling that closely aligns with
    /// object-oriented practices.
    ///
    /// See [`ServerEventHandler`] for more information and examples.
    pub fn with_event_handler<H>(
        self,
        handler: H,
    ) -> ServerBuilder<
        ServerSending<S>,
        ServerReceiving<R>,
        ServerEventReporting<ServerEventReportingHandler<R, H>>,
    >
    where
        H: ServerEventHandler<R>,
    {
        ServerBuilder {
            phantom_send: PhantomData,
            phantom_receive: PhantomData,
            event_reporting: ServerEventReporting(ServerEventReportingHandler {
                handler,
                phantom_receive: PhantomData,
            }),
        }
    }

    /// Configures the server to receive events via a channel.
    ///
    /// This is the most versatile event handling strategy. In fact, all other
    /// event handling options use this implementation under the hood.
    /// Because of its flexibility, this will typically be the desired
    /// approach.
    pub fn with_event_channel(
        self,
    ) -> ServerBuilder<
        ServerSending<S>,
        ServerReceiving<R>,
        ServerEventReporting<ServerEventReportingChannel>,
    > {
        ServerBuilder {
            phantom_send: PhantomData,
            phantom_receive: PhantomData,
            event_reporting: ServerEventReporting(ServerEventReportingChannel),
        }
    }
}

impl<S, R>
    ServerBuilder<
        ServerSending<S>,
        ServerReceiving<R>,
        ServerEventReporting<ServerEventReportingCallbacks<R>>,
    >
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    /// Starts the server. This is effectively identical to
    /// `Server::start(...)`.
    pub async fn start<A>(self, addr: A) -> io::Result<ServerHandle<S>>
    where
        A: ToSocketAddrs,
    {
        let (server, mut server_events) = Server::<S, R>::start(addr).await?;
        let callbacks = self.event_reporting.0 .0;

        tokio::spawn(async move {
            while let Some(event) = server_events.next().await {
                match event {
                    ServerEvent::Connect { client_id } => {
                        if let Some(ref connect) = callbacks.connect {
                            tokio::spawn((*connect)(client_id));
                        }
                    }
                    ServerEvent::Disconnect { client_id } => {
                        if let Some(ref disconnect) = callbacks.disconnect {
                            tokio::spawn((*disconnect)(client_id));
                        }
                    }
                    ServerEvent::Receive { client_id, data } => {
                        if let Some(ref receive) = callbacks.receive {
                            tokio::spawn((*receive)(client_id, data));
                        }
                    }
                    ServerEvent::Stop => {
                        if let Some(ref stop) = callbacks.stop {
                            tokio::spawn((*stop)());
                        }
                    }
                }
            }
        });

        Ok(server)
    }
}

impl<S, R, H>
    ServerBuilder<
        ServerSending<S>,
        ServerReceiving<R>,
        ServerEventReporting<ServerEventReportingHandler<R, H>>,
    >
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
    H: ServerEventHandler<R> + 'static,
{
    /// Starts the server. This is effectively identical to
    /// `Server::start(...)`.
    pub async fn start<A>(self, addr: A) -> io::Result<ServerHandle<S>>
    where
        A: ToSocketAddrs,
    {
        let (server, mut server_events) = Server::<S, R>::start(addr).await?;
        let handler = Arc::new(self.event_reporting.0.handler);

        tokio::spawn(async move {
            while let Some(event) = server_events.next().await {
                match event {
                    ServerEvent::Connect { client_id } => {
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move {
                            handler.on_connect(client_id).await;
                        });
                    }
                    ServerEvent::Disconnect { client_id } => {
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move {
                            handler.on_disconnect(client_id).await;
                        });
                    }
                    ServerEvent::Receive { client_id, data } => {
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move {
                            handler.on_receive(client_id, data).await;
                        });
                    }
                    ServerEvent::Stop => {
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move {
                            handler.on_stop().await;
                        });
                    }
                }
            }
        });

        Ok(server)
    }
}

impl<S, R>
    ServerBuilder<
        ServerSending<S>,
        ServerReceiving<R>,
        ServerEventReporting<ServerEventReportingChannel>,
    >
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    /// Starts the server. This is effectively identical to
    /// `Server::start(...)`.
    pub async fn start<A>(
        self,
        addr: A,
    ) -> io::Result<(ServerHandle<S>, EventStream<ServerEvent<R>>)>
    where
        A: ToSocketAddrs,
    {
        Server::<S, R>::start(addr).await
    }
}

/// A command sent from the server handle to the background server task.
pub enum ServerCommand<S>
where
    S: Serialize + Send + 'static,
{
    /// Stop the server.
    Stop,
    /// Send data to a client.
    Send {
        /// The ID of the client to send the data to.
        client_id: usize,
        /// The data to send.
        data: S,
    },
    /// Send data to all clients.
    SendAll {
        /// The data to send.
        data: S,
    },
    /// Get the local server address.
    GetAddr,
    /// Get the address of a client.
    GetClientAddr {
        /// The ID of the client.
        client_id: usize,
    },
    /// Disconnect a client from the server.
    RemoveClient {
        /// The ID of the client.
        client_id: usize,
    },
}

/// The return value of a command executed on the background server task.
pub enum ServerCommandReturn {
    /// Stop return value.
    Stop(io::Result<()>),
    /// Sent data return value.
    Send(io::Result<()>),
    /// Sent data to all return value.
    SendAll(io::Result<()>),
    /// Local server address return value.
    GetAddr(io::Result<SocketAddr>),
    /// Client address return value.
    GetClientAddr(io::Result<SocketAddr>),
    /// Disconnect client return value.
    RemoveClient(io::Result<()>),
}

/// A command sent from the server background task to a client background task.
pub enum ServerClientCommand {
    /// Send data to the client.
    Send {
        /// The serialized data to send.
        data: Arc<[u8]>,
    },
    /// Get the address of the client.
    GetAddr,
    /// Disconnect the client.
    Remove,
}

/// The return value of a command executed on a client background task.
pub enum ServerClientCommandReturn {
    /// Send data return value.
    Send(io::Result<()>),
    /// Client address return value.
    GetAddr(io::Result<SocketAddr>),
    /// Disconnect client return value.
    Remove(io::Result<()>),
}

/// An event from the server.
///
/// ```no_run
/// use rustdtp::*;
///
/// #[tokio::main]
/// async fn main() {
///     // Create the server
///     let (mut server, mut server_events) = Server::builder()
///         .sending::<()>()
///         .receiving::<String>()
///         .with_event_channel()
///         .start(("0.0.0.0", 0))
///         .await
///         .unwrap();
///
///     // Iterate over events
///     while let Some(event) = server_events.next().await {
///         match event {
///             ServerEvent::Connect { client_id } => {
///                 println!("Client with ID {} connected", client_id);
///             }
///             ServerEvent::Disconnect { client_id } => {
///                 println!("Client with ID {} disconnected", client_id);
///             }
///             ServerEvent::Receive { client_id, data } => {
///                 println!("Client with ID {} sent: {}", client_id, data);
///             }
///             ServerEvent::Stop => {
///                 // No more events will be sent, and the loop will end
///                 println!("Server closed");
///             }
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub enum ServerEvent<R>
where
    R: DeserializeOwned + Send + 'static,
{
    /// A client connected.
    Connect {
        /// The ID of the client that connected.
        client_id: usize,
    },
    /// A client disconnected.
    Disconnect {
        /// The ID of the client that disconnected.
        client_id: usize,
    },
    /// Data received from a client.
    Receive {
        /// The ID of the client that sent the data.
        client_id: usize,
        /// The data itself.
        data: R,
    },
    /// Server stopped.
    Stop,
}

/// A handle to the server.
pub struct ServerHandle<S>
where
    S: Serialize + Send + 'static,
{
    /// The channel through which commands can be sent to the background task.
    server_command_sender: CommandChannelSender<ServerCommand<S>, ServerCommandReturn>,
    /// The handle to the background task.
    server_task_handle: JoinHandle<io::Result<()>>,
}

impl<S> ServerHandle<S>
where
    S: Serialize + Send + 'static,
{
    /// Stop the server, disconnect all clients, and shut down all network interfaces.
    ///
    /// Returns a result of the error variant if an error occurred while disconnecting clients.
    ///
    /// ```no_run
    /// use rustdtp::*;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     // Create the server
    ///     let (mut server, mut server_events) = Server::builder()
    ///         .sending::<()>()
    ///         .receiving::<String>()
    ///         .with_event_channel()
    ///         .start(("0.0.0.0", 0))
    ///         .await
    ///         .unwrap();
    ///
    ///     // Wait for events until a client requests the server be stopped
    ///     while let Some(event) = server_events.next().await {
    ///         match event {
    ///             // Stop the server when a client requests it be stopped
    ///             ServerEvent::Receive { client_id, data } => {
    ///                 if data.as_str() == "Stop the server!" {
    ///                     println!("Server stop requested");
    ///                     server.stop().await.unwrap();
    ///                     break;
    ///                 }
    ///             }
    ///             _ => {}  // Do nothing for other events
    ///         }
    ///     }
    ///
    ///     // The last event should be a stop event
    ///     assert!(matches!(server_events.next().await.unwrap(), ServerEvent::Stop));
    /// }
    /// ```
    pub async fn stop(mut self) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::Stop)
            .await?;
        self.server_task_handle.await.unwrap()?;
        unwrap_enum!(value, ServerCommandReturn::Stop)
    }

    /// Send data to a client.
    ///
    /// `client_id`: the ID of the client to send the data to.
    /// `data`: the data to send.
    ///
    /// Returns a result of the error variant if an error occurred while sending.
    ///
    /// ```no_run
    /// use rustdtp::*;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     // Create the server
    ///     let (mut server, mut server_events) = Server::builder()
    ///         .sending::<String>()
    ///         .receiving::<()>()
    ///         .with_event_channel()
    ///         .start(("0.0.0.0", 0))
    ///         .await
    ///         .unwrap();
    ///
    ///     // Iterate over events
    ///     while let Some(event) = server_events.next().await {
    ///         match event {
    ///             // When a client connects, send a greeting
    ///             ServerEvent::Connect { client_id } => {
    ///                 server.send(client_id, format!("Hello, client {}!", client_id)).await.unwrap();
    ///             }
    ///             _ => {}  // Do nothing for other events
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn send(&mut self, client_id: usize, data: S) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::Send { client_id, data })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::Send)
    }

    /// Send data to all clients.
    ///
    /// `data`: the data to send.
    ///
    /// Returns a result of the error variant if an error occurred while sending.
    ///
    /// ```no_run
    /// use rustdtp::*;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     // Create the server
    ///     let (mut server, mut server_events) = Server::builder()
    ///         .sending::<String>()
    ///         .receiving::<()>()
    ///         .with_event_channel()
    ///         .start(("0.0.0.0", 0))
    ///         .await
    ///         .unwrap();
    ///
    ///     // Iterate over events
    ///     while let Some(event) = server_events.next().await {
    ///         match event {
    ///             // When a client connects, notify all clients
    ///             ServerEvent::Connect { client_id } => {
    ///                 server.send_all(format!("A new client with ID {} has joined!", client_id)).await.unwrap();
    ///             }
    ///             _ => {}  // Do nothing for other events
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn send_all(&mut self, data: S) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::SendAll { data })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::SendAll)
    }

    /// Get the address the server is listening on.
    ///
    /// Returns a result containing the address the server is listening on, or the error variant if an error occurred.
    ///
    /// ```no_run
    /// use rustdtp::*;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     // Create the server
    ///     let (mut server, mut server_events) = Server::builder()
    ///         .sending::<()>()
    ///         .receiving::<()>()
    ///         .with_event_channel()
    ///         .start(("0.0.0.0", 0))
    ///         .await
    ///         .unwrap();
    ///
    ///     // Get the server address
    ///     let addr = server.get_addr().await.unwrap();
    ///     println!("Server listening on {}", addr);
    /// }
    /// ```
    pub async fn get_addr(&mut self) -> io::Result<SocketAddr> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::GetAddr)
            .await?;
        unwrap_enum!(value, ServerCommandReturn::GetAddr)
    }

    /// Get the address of a connected client.
    ///
    /// `client_id`: the ID of the client.
    ///
    /// Returns a result containing the address of the client, or the error variant if the client ID is invalid.
    ///
    /// ```no_run
    /// use rustdtp::*;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     // Create the server
    ///     let (mut server, mut server_events) = Server::builder()
    ///         .sending::<()>()
    ///         .receiving::<()>()
    ///         .with_event_channel()
    ///         .start(("0.0.0.0", 0))
    ///         .await
    ///         .unwrap();
    ///
    ///     // Iterate over events
    ///     while let Some(event) = server_events.next().await {
    ///         match event {
    ///             // When a client connects, get their address
    ///             ServerEvent::Connect { client_id } => {
    ///                 let addr = server.get_client_addr(client_id).await.unwrap();
    ///                 println!("Client with ID {} connected from {}", client_id, addr);
    ///             }
    ///             _ => {}  // Do nothing for other events
    ///         }
    ///     }
    /// }
    pub async fn get_client_addr(&mut self, client_id: usize) -> io::Result<SocketAddr> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::GetClientAddr { client_id })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::GetClientAddr)
    }

    /// Disconnect a client from the server.
    ///
    /// `client_id`: the ID of the client.
    ///
    /// Returns a result of the error variant if an error occurred while disconnecting the client, or if the client ID is invalid.
    ///
    /// ```no_run
    /// use rustdtp::*;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     // Create the server
    ///     let (mut server, mut server_events) = Server::builder()
    ///         .sending::<String>()
    ///         .receiving::<i32>()
    ///         .with_event_channel()
    ///         .start(("0.0.0.0", 0))
    ///         .await
    ///         .unwrap();
    ///
    ///     // Iterate over events
    ///     while let Some(event) = server_events.next().await {
    ///         match event {
    ///             // Disconnect a client if they send an even number
    ///             ServerEvent::Receive { client_id, data } => {
    ///                 if data % 2 == 0 {
    ///                     println!("Disconnecting client with ID {}", client_id);
    ///                     server.send(client_id, "Even numbers are not allowed".to_owned()).await.unwrap();
    ///                     server.remove_client(client_id).await.unwrap();
    ///                 }
    ///             }
    ///             _ => {}  // Do nothing for other events
    ///         }
    ///     }
    ///
    ///     // The last event should be a stop event
    ///     assert!(matches!(server_events.next().await.unwrap(), ServerEvent::Stop));
    /// }
    /// ```
    pub async fn remove_client(&mut self, client_id: usize) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::RemoveClient { client_id })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::RemoveClient)
    }
}

/// A socket server.
///
/// The server takes two generic parameters:
///
/// - `S`: the type of data that will be **sent** to clients.
/// - `R`: the type of data that will be **received** from clients.
///
/// Both types must be serializable in order to be sent through the socket. When creating clients, the types should be swapped, since the server's send type will be the client's receive type and vice versa.
///
/// ```no_run
/// use rustdtp::*;
///
/// #[tokio::main]
/// async fn main() {
///     // Create a server that receives strings and returns the length of each string
///     let (mut server, mut server_events) = Server::builder()
///         .sending::<usize>()
///         .receiving::<String>()
///         .with_event_channel()
///         .start(("0.0.0.0", 0))
///         .await
///         .unwrap();
///
///     // Iterate over events
///     while let Some(event) = server_events.next().await {
///         match event {
///             ServerEvent::Connect { client_id } => {
///                 println!("Client with ID {} connected", client_id);
///             }
///             ServerEvent::Disconnect { client_id } => {
///                 println!("Client with ID {} disconnected", client_id);
///             }
///             ServerEvent::Receive { client_id, data } => {
///                 // Send back the length of the string
///                 server.send(client_id, data.len()).await.unwrap();
///             }
///             ServerEvent::Stop => {
///                 // No more events will be sent, and the loop will end
///                 println!("Server closed");
///             }
///         }
///     }
/// }
/// ```
pub struct Server<S, R>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    /// Phantom value for `S`.
    phantom_send: PhantomData<S>,
    /// Phantom value for `R`.
    phantom_receive: PhantomData<R>,
}

impl Server<(), ()> {
    /// Constructs a server builder. Use this for a clearer, more explicit,
    /// and more featureful server configuration. See [`ServerBuilder`] for
    /// more information.
    pub fn builder(
    ) -> ServerBuilder<ServerSendingUnknown, ServerReceivingUnknown, ServerEventReportingUnknown>
    {
        ServerBuilder::new()
    }
}

impl<S, R> Server<S, R>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    /// Start a socket server.
    ///
    /// `addr`: the address for the server to listen on.
    ///
    /// Returns a result containing a handle to the server and a channel from which to receive server events, or the error variant if an error occurred while starting the server.
    ///
    /// ```no_run
    /// use rustdtp::*;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let (mut server, mut server_events) = Server::builder()
    ///         .sending::<()>()
    ///         .receiving::<()>()
    ///         .with_event_channel()
    ///         .start(("0.0.0.0", 0))
    ///         .await
    ///         .unwrap();
    /// }
    /// ```
    ///
    /// Neither the server handle nor the event receiver should be dropped until the server has been stopped. Prematurely dropping either one can cause unintended behavior.
    pub async fn start<A>(addr: A) -> io::Result<(ServerHandle<S>, EventStream<ServerEvent<R>>)>
    where
        A: ToSocketAddrs,
    {
        // Server TCP listener
        let listener = TcpListener::bind(addr).await?;
        // Channels for sending commands from the server handle to the background server task
        let (server_command_sender, server_command_receiver) = command_channel();
        // Channels for sending event notifications from the background server task
        let (server_event_sender, server_event_receiver) = channel(CHANNEL_BUFFER_SIZE);

        // Start the background server task, saving the join handle for when the server is stopped
        let server_task_handle = tokio::spawn(server_handler(
            listener,
            server_event_sender,
            server_command_receiver,
        ));

        // Create a handle for the server
        let server_handle = ServerHandle {
            server_command_sender,
            server_task_handle,
        };

        // Create an event stream for the server
        let server_event_stream = EventStream::new(server_event_receiver);

        Ok((server_handle, server_event_stream))
    }
}

/// The server client loop. Handles received data and commands.
async fn server_client_loop<R>(
    client_id: usize,
    mut socket: TcpStream,
    aes_key: [u8; AES_KEY_SIZE],
    server_client_event_sender: Sender<ServerEvent<R>>,
    mut client_command_receiver: CommandChannelReceiver<
        ServerClientCommand,
        ServerClientCommandReturn,
    >,
) -> io::Result<()>
where
    R: DeserializeOwned + Send + 'static,
{
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
                let encrypted_data_size = decode_message_size(&size_buffer);
                // Initialize the buffer for the data portion of the message
                let mut encrypted_data_buffer = vec![0; encrypted_data_size];

                // Read the data portion from the client socket, returning an error if the
                // socket could not be read
                let n_data = data_read_timeout! {
                    socket.read(&mut encrypted_data_buffer)
                }??;

                // If there were no bytes read, or if there were fewer bytes read than there
                // should have been, close the socket
                if n_data != encrypted_data_size {
                    socket.shutdown().await?;
                    break;
                }

                // Decrypt the data
                let data_buffer = match aes_decrypt(aes_key, encrypted_data_buffer.into()).await {
                    Ok(val) => Ok(val),
                    Err(e) => generic_io_error(format!("failed to decrypt data: {}", e)),
                }?;

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
                                let value = 'val: {
                                    // Encrypt the serialized data
                                    let encrypted_data_buffer = break_on_err!(into_generic_io_result(aes_encrypt(aes_key, data).await), 'val);
                                    // Encode the message size to a buffer
                                    let size_buffer = encode_message_size(encrypted_data_buffer.len());

                                    // Initialize the message buffer
                                    let mut buffer = vec![];
                                    // Extend the buffer to contain the payload size
                                    buffer.extend_from_slice(&size_buffer);
                                    // Extend the buffer to contain the payload data
                                    buffer.extend(&encrypted_data_buffer);

                                    // Write the data to the client socket
                                    let n = break_on_err!(socket.write(&buffer).await, 'val);
                                    // Flush the stream
                                    break_on_err!(socket.flush().await, 'val);

                                    // If there were no bytes written, or if there were fewer
                                    // bytes written than there should have been, close the
                                    // socket
                                    if n != buffer.len() {
                                        generic_io_error("failed to write data to socket")
                                    } else {
                                        Ok(())
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

    Ok(())
}

/// Starts a server client loop in the background.
async fn server_client_handler<R>(
    client_id: usize,
    mut socket: TcpStream,
    server_client_event_sender: Sender<ServerEvent<R>>,
    client_cleanup_sender: Sender<usize>,
) -> io::Result<(
    CommandChannelSender<ServerClientCommand, ServerClientCommandReturn>,
    JoinHandle<io::Result<()>>,
)>
where
    R: DeserializeOwned + Send + 'static,
{
    // Generate RSA keys
    let (rsa_pub, rsa_priv) = into_generic_io_result(rsa_keys().await)?;
    // Convert the RSA public key into a string...
    let rsa_pub_str =
        into_generic_io_result(rsa_pub.to_public_key_pem(rsa::pkcs1::LineEnding::LF))?;
    // ...and then into bytes
    let rsa_pub_bytes = rsa_pub_str.as_bytes();
    // Create the buffer containing the RSA public key and its size
    let mut rsa_pub_buffer = encode_message_size(rsa_pub_bytes.len()).to_vec();
    // Extend the buffer with the RSA public key bytes
    rsa_pub_buffer.extend(rsa_pub_bytes);
    // Send the RSA public key to the client
    let n = socket.write(&rsa_pub_buffer).await?;
    // Flush the stream
    socket.flush().await?;

    // If there were no bytes written, or if there were fewer
    // bytes written than there should have been, close the
    // socket and exit
    if n != rsa_pub_buffer.len() {
        socket.shutdown().await?;
        return generic_io_error("failed to write RSA public key data to socket");
    }

    // Buffer in which to receive the size portion of the AES key
    let mut aes_key_size_buffer = [0; LEN_SIZE];
    // Read the AES key from the client
    let n_size = handshake_timeout! {
        socket.read(&mut aes_key_size_buffer)
    }??;

    // If there were no bytes read, or if there were fewer bytes read than there
    // should have been, close the socket and exit
    if n_size != LEN_SIZE {
        socket.shutdown().await?;
        return generic_io_error("failed to read AES key size from socket");
    };

    // Decode the size portion of the AES key
    let aes_key_size = decode_message_size(&aes_key_size_buffer);
    // Initialize the buffer for the AES key
    let mut aes_key_buffer = vec![0; aes_key_size];

    // Read the AES key portion from the client socket, returning an error if the
    // socket could not be read
    let n_aes_key = data_read_timeout! {
        socket.read(&mut aes_key_buffer)
    }??;

    // If there were no bytes read, or if there were fewer bytes read than there
    // should have been, close the socket and exit
    if n_aes_key != aes_key_size {
        socket.shutdown().await?;
        return generic_io_error("failed to read AES key data from socket");
    }

    // Decrypt the AES key
    let aes_key_decrypted =
        into_generic_io_result(rsa_decrypt(rsa_priv, aes_key_buffer.into()).await)?;

    // Assert that the AES key is the correct size
    let aes_key: [u8; AES_KEY_SIZE] = match aes_key_decrypted.try_into() {
        Ok(val) => Ok(val),
        Err(_e) => generic_io_error("unexpected size for AES key"),
    }?;

    // Channels for sending commands from the background server task to a background client task
    let (client_command_sender, client_command_receiver) = command_channel();

    // Start a background client task, saving the join handle for when the server is stopped
    let client_task_handle = tokio::spawn(async move {
        let res = server_client_loop(
            client_id,
            socket,
            aes_key,
            server_client_event_sender,
            client_command_receiver,
        )
        .await;

        // Tell the server to clean up after the client, ignoring failures, since a failure
        // indicates that the server has probably closed
        if let Err(_e) = client_cleanup_sender.send(client_id).await {}

        res
    });

    Ok((client_command_sender, client_task_handle))
}

/// The server loop. Handles incoming connections and commands.
async fn server_loop<S, R>(
    listener: TcpListener,
    server_event_sender: Sender<ServerEvent<R>>,
    mut server_command_receiver: CommandChannelReceiver<ServerCommand<S>, ServerCommandReturn>,
    client_command_senders: &mut HashMap<
        usize,
        CommandChannelSender<ServerClientCommand, ServerClientCommandReturn>,
    >,
    client_join_handles: &mut HashMap<usize, JoinHandle<io::Result<()>>>,
) -> io::Result<()>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    // ID assigned to the next client
    let mut next_client_id = 0usize;
    // Channel for indicating that a client needs to be cleaned up after
    let (server_client_cleanup_sender, mut server_client_cleanup_receiver) =
        channel::<usize>(CHANNEL_BUFFER_SIZE);

    // Server loop
    loop {
        // Await new clients connecting,
        // commands from the server handle,
        // and notifications of clients disconnecting
        tokio::select! {
            // Accept a connecting client
            accept_value = listener.accept() => {
                // Get the client socket, exiting if an error occurs
                let (socket, _) = accept_value?;
                // New client ID
                let client_id = next_client_id;
                // Increment next client ID
                next_client_id += 1;
                // Clone the event sender so the background client tasks can send events
                let server_client_event_sender = server_event_sender.clone();
                // Clone the client cleanup sender to the background client tasks can be cleaned up properly
                let client_cleanup_sender = server_client_cleanup_sender.clone();

                // Handle the new connection
                match server_client_handler(client_id, socket, server_client_event_sender, client_cleanup_sender).await {
                    Ok((client_command_sender, client_task_handle)) => {
                        // Keep track of client command senders
                        client_command_senders.insert(client_id, client_command_sender);
                        // Keep track of client task handles
                        client_join_handles.insert(client_id, client_task_handle);

                        // Send an event to note that a client has connected successfully
                        if let Err(_e) = server_event_sender
                            .send(ServerEvent::Connect { client_id })
                            .await
                        {
                            // Server is probably closed
                            break;
                        }
                    },
                    Err(e) => {
                        if cfg!(test) {
                            // If testing, fail
                            Err(e)?
                        } else {
                            // If not testing, ignore client handshake errors
                        }
                    }
                }
            },
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
                                _ = server_command_receiver.command_return(ServerCommandReturn::Stop(Ok(()))).await;

                                // Break the server loop, the clients will be disconnected before the task ends
                                break;
                            },
                            ServerCommand::Send { client_id, data } => {
                                let value = match client_command_senders.get_mut(&client_id) {
                                    Some(client_command_sender) => {
                                        // Pre-serialize the data so that it only needs to be serialized once when
                                        // sending to multiple clients
                                        match into_generic_io_result(serde_json::to_vec(&data)) {
                                            Ok(serialized_data) => {
                                                // Turn `Vec<u8>` into `Arc<[u8]>`, making it more easily shareable
                                                let shareable_data = Arc::<[u8]>::from(serialized_data);

                                                match client_command_sender.send_command(ServerClientCommand::Send { data: shareable_data }).await {
                                                    Ok(return_value) => unwrap_enum!(return_value, ServerClientCommandReturn::Send),
                                                    Err(_e) => {
                                                        // The channel is closed, and the client has probably been
                                                        // disconnected, so the error can be ignored
                                                        Ok(())
                                                    },
                                                }
                                            }
                                            Err(e) => Err(e),
                                        }
                                    },
                                    None => generic_io_error("invalid client"),
                                };

                                // If a command fails to send, the client has probably disconnected,
                                // and the error can be ignored
                                _ = server_command_receiver.command_return(ServerCommandReturn::Send(value)).await;
                            },
                            ServerCommand::SendAll { data } => {
                                let value = {
                                    // Pre-serialize the data so that it only needs to be serialized once when sending to
                                    // multiple clients
                                    match into_generic_io_result(serde_json::to_vec(&data)) {
                                        Ok(serialized_data) => {
                                            // Turn `Vec<u8>` into `Arc<[u8]>`, making it more easily shareable
                                            let shareable_data = Arc::<[u8]>::from(serialized_data);

                                            let send_futures = client_command_senders.iter_mut().map(|(_client_id, client_command_sender)| async {
                                                match client_command_sender.send_command(ServerClientCommand::Send { data: Arc::clone(&shareable_data) }).await {
                                                    Ok(return_value) => unwrap_enum!(return_value, ServerClientCommandReturn::Send),
                                                    Err(_e) => {
                                                        // The channel is closed, and the client has probably been
                                                        // disconnected, so the error can be ignored
                                                        Ok(())
                                                    }
                                                }
                                            });

                                            let resolved = futures::future::join_all(send_futures).await;
                                            resolved.into_iter().collect::<io::Result<Vec<_>>>().map(|_| ())
                                        }
                                        Err(e) => Err(e),
                                    }
                                };

                                // If a command fails to send, the client has probably disconnected,
                                // and the error can be ignored
                                _ = server_command_receiver.command_return(ServerCommandReturn::SendAll(value)).await;
                            },
                            ServerCommand::GetAddr => {
                                // Get the server listener's address
                                let addr = listener.local_addr();

                                // If a command fails to send, the client has probably disconnected,
                                // and the error can be ignored
                                _ = server_command_receiver.command_return(ServerCommandReturn::GetAddr(addr)).await;
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
                                _ = server_command_receiver.command_return(ServerCommandReturn::GetClientAddr(value)).await;
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
                                _ = server_command_receiver.command_return(ServerCommandReturn::RemoveClient(value)).await;
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
                            if let Err(e) = handle.await.unwrap() {
                                if cfg!(test) {
                                    // If testing, fail
                                    Err(e)?
                                } else {
                                    // If not testing, ignore client handler errors
                                }
                            }
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

    Ok(())
}

/// Starts the server loop task in the background.
async fn server_handler<S, R>(
    listener: TcpListener,
    server_event_sender: Sender<ServerEvent<R>>,
    server_command_receiver: CommandChannelReceiver<ServerCommand<S>, ServerCommandReturn>,
) -> io::Result<()>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    // Collection of channels for sending commands from the background server task to a background client task
    let mut client_command_senders: HashMap<
        usize,
        CommandChannelSender<ServerClientCommand, ServerClientCommandReturn>,
    > = HashMap::new();
    // Background client task join handles
    let mut client_join_handles: HashMap<usize, JoinHandle<io::Result<()>>> = HashMap::new();

    // Wrap server loop in a block to catch all exit scenarios
    let server_exit = server_loop(
        listener,
        server_event_sender.clone(),
        server_command_receiver,
        &mut client_command_senders,
        &mut client_join_handles,
    )
    .await;

    // Send a remove command to all clients
    futures::future::join_all(client_command_senders.into_values().map(
        |mut client_command_sender| async move {
            // If a command fails to send, the client has probably disconnected already,
            // and the error can be ignored
            _ = client_command_sender
                .send_command(ServerClientCommand::Remove)
                .await;
        },
    ))
    .await;

    // Join all background client tasks before exiting
    futures::future::join_all(client_join_handles.into_values().map(|handle| async move {
        if let Err(e) = handle.await.unwrap() {
            if cfg!(test) {
                // If testing, fail
                Err(e)?
            } else {
                // If not testing, ignore client handler errors
            }
        }

        Ok(())
    }))
    .await
    .into_iter()
    .collect::<io::Result<Vec<_>>>()?;

    // Send a stop event, ignoring send errors
    if let Err(_e) = server_event_sender.send(ServerEvent::Stop).await {}

    // Return server loop result
    server_exit
}
