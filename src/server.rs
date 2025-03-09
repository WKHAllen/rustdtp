//! Protocol server implementation.

use super::command_channel::*;
use super::timeout::*;
use crate::crypto::*;
use crate::util::*;
use rsa::pkcs8::EncodePublicKey;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::mpsc::{channel, Receiver, Sender};
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
/// closure returning a thread-safe future. The future will be awaited by the
/// runtime.
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
///             .on_connect(move |client_id| async move {
///                 // some async operation...
///                 println!("Client with ID {} connected", client_id);
///             })
///             .on_disconnect(move |client_id| async move {
///                 // some async operation...
///                 println!("Client with ID {} disconnected", client_id);
///             })
///             .on_receive(move |client_id, data| async move {
///                 // some async operation...
///                 println!("Received data from client with ID {}: {}", client_id, data);
///             })
///             .on_stop(move || async move {
///                 // some async operation...
///                 println!("Server closed");
///             })
///     )
///     .start(("0.0.0.0", 0))
///     .await
///     .unwrap();
/// # }
/// ```
#[allow(clippy::type_complexity)]
#[must_use = "event callbacks do nothing unless you configure them for a server"]
pub struct ServerEventCallbacks<R>
where
    R: DeserializeOwned + 'static,
{
    /// The `connect` event callback.
    connect: Option<Arc<dyn Fn(usize) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>>,
    /// The `disconnect` event callback.
    disconnect:
        Option<Arc<dyn Fn(usize) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>>,
    /// The `receive` event callback.
    receive:
        Option<Arc<dyn Fn(usize, R) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>>,
    /// The `stop` event callback.
    stop: Option<Arc<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>>,
}

impl<R> ServerEventCallbacks<R>
where
    R: DeserializeOwned + 'static,
{
    /// Creates a new server event callbacks configuration with all callbacks
    /// empty.
    pub const fn new() -> Self {
        Self {
            connect: None,
            disconnect: None,
            receive: None,
            stop: None,
        }
    }

    /// Registers a callback on the `connect` event.
    pub fn on_connect<C, F>(mut self, callback: C) -> Self
    where
        C: Fn(usize) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        self.connect = Some(Arc::new(move |client_id| Box::pin((callback)(client_id))));
        self
    }

    /// Registers a callback on the `disconnect` event.
    pub fn on_disconnect<C, F>(mut self, callback: C) -> Self
    where
        C: Fn(usize) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        self.disconnect = Some(Arc::new(move |client_id| Box::pin((callback)(client_id))));
        self
    }

    /// Registers a callback on the `receive` event.
    pub fn on_receive<C, F>(mut self, callback: C) -> Self
    where
        C: Fn(usize, R) -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        self.receive = Some(Arc::new(move |client_id, data| {
            Box::pin((callback)(client_id, data))
        }));
        self
    }

    /// Registers a callback on the `stop` event.
    pub fn on_stop<C, F>(mut self, callback: C) -> Self
    where
        C: Fn() -> F + Send + Sync + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        self.stop = Some(Arc::new(move || Box::pin((callback)())));
        self
    }
}

impl<R> Default for ServerEventCallbacks<R>
where
    R: DeserializeOwned + 'static,
{
    fn default() -> Self {
        Self::new()
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
/// must be `Send + Sync`, and that all event method futures must be `Send`.
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
pub trait ServerEventHandler<R>
where
    Self: Send + Sync,
    R: DeserializeOwned + 'static,
{
    /// Handles the `connect` event.
    #[allow(unused_variables)]
    fn on_connect(&self, client_id: usize) -> impl Future<Output = ()> + Send {
        async {}
    }

    /// Handles the `disconnect` event.
    #[allow(unused_variables)]
    fn on_disconnect(&self, client_id: usize) -> impl Future<Output = ()> + Send {
        async {}
    }

    /// Handles the `receive` event.
    #[allow(unused_variables)]
    fn on_receive(&self, client_id: usize, data: R) -> impl Future<Output = ()> + Send {
        async {}
    }

    /// Handles the `stop` event.
    fn on_stop(&self) -> impl Future<Output = ()> + Send {
        async {}
    }
}

/// Unknown server sending type.
pub struct ServerSendingUnknown;

/// Known server sending type, stored as the type parameter `S`.
pub struct ServerSending<S>(PhantomData<fn() -> S>)
where
    S: Serialize + 'static;

/// A server sending marker trait.
trait ServerSendingConfig {}

impl ServerSendingConfig for ServerSendingUnknown {}

impl<S> ServerSendingConfig for ServerSending<S> where S: Serialize + 'static {}

/// Unknown server receiving type.
pub struct ServerReceivingUnknown;

/// Known server receiving type, stored as the type parameter `R`.
pub struct ServerReceiving<R>(PhantomData<fn() -> R>)
where
    R: DeserializeOwned + 'static;

/// A server receiving marker trait.
trait ServerReceivingConfig {}

impl ServerReceivingConfig for ServerReceivingUnknown {}

impl<R> ServerReceivingConfig for ServerReceiving<R> where R: DeserializeOwned + 'static {}

/// Unknown server event reporting type.
pub struct ServerEventReportingUnknown;

/// Known server event reporting type, stored as the type parameter `E`.
pub struct ServerEventReporting<E>(E);

/// Server event reporting via callbacks.
pub struct ServerEventReportingCallbacks<R>(ServerEventCallbacks<R>)
where
    R: DeserializeOwned + 'static;

/// Server event reporting via an event handler.
pub struct ServerEventReportingHandler<R, H>
where
    R: DeserializeOwned + 'static,
    H: ServerEventHandler<R>,
{
    /// The event handler instance.
    handler: H,
    /// Phantom `R` owner.
    phantom_receive: PhantomData<fn() -> R>,
}

/// Server event reporting via a channel.
pub struct ServerEventReportingChannel;

/// A server event reporting marker trait.
trait ServerEventReportingConfig {}

impl ServerEventReportingConfig for ServerEventReportingUnknown {}

impl<R> ServerEventReportingConfig for ServerEventReporting<ServerEventReportingCallbacks<R>> where
    R: DeserializeOwned + 'static
{
}

impl<R, H> ServerEventReportingConfig for ServerEventReporting<ServerEventReportingHandler<R, H>>
where
    R: DeserializeOwned + 'static,
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
#[must_use = "server builders do nothing unless `start` is called"]
pub struct ServerBuilder<SC, RC, EC>
where
    SC: ServerSendingConfig,
    RC: ServerReceivingConfig,
    EC: ServerEventReportingConfig,
{
    /// Phantom marker for `SC` and `RC`.
    marker: PhantomData<fn() -> (SC, RC)>,
    /// The event reporting configuration.
    event_reporting: EC,
}

impl ServerBuilder<ServerSendingUnknown, ServerReceivingUnknown, ServerEventReportingUnknown> {
    /// Creates a new server builder.
    pub const fn new() -> Self {
        Self {
            marker: PhantomData,
            event_reporting: ServerEventReportingUnknown,
        }
    }
}

impl Default
    for ServerBuilder<ServerSendingUnknown, ServerReceivingUnknown, ServerEventReportingUnknown>
{
    fn default() -> Self {
        Self::new()
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
        S: Serialize + 'static,
    {
        ServerBuilder {
            marker: PhantomData,
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
        R: DeserializeOwned + 'static,
    {
        ServerBuilder {
            marker: PhantomData,
            event_reporting: self.event_reporting,
        }
    }
}

impl<S, R> ServerBuilder<ServerSending<S>, ServerReceiving<R>, ServerEventReportingUnknown>
where
    S: Serialize + 'static,
    R: DeserializeOwned + 'static,
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
        R: DeserializeOwned + 'static,
    {
        ServerBuilder {
            marker: PhantomData,
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
            marker: PhantomData,
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
            marker: PhantomData,
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
    S: Serialize + 'static,
    R: DeserializeOwned + 'static,
{
    /// Starts the server. This is effectively identical to [`Server::start`].
    ///
    /// # Errors
    ///
    /// The set of errors that can occur are identical to that of
    /// [`Server::start`].
    #[allow(clippy::future_not_send)]
    pub async fn start<A>(self, addr: A) -> io::Result<ServerHandle<S>>
    where
        A: ToSocketAddrs,
    {
        let (server, mut server_events) = Server::<S, R>::start(addr).await?;
        let callbacks = self.event_reporting.0 .0;

        tokio::spawn(async move {
            while let Ok(event) = server_events.next_raw().await {
                match event {
                    ServerEventRawSafe::Connect { client_id } => {
                        if let Some(ref connect) = callbacks.connect {
                            let connect = Arc::clone(connect);
                            tokio::spawn(async move {
                                (*connect)(client_id).await;
                            });
                        }
                    }
                    ServerEventRawSafe::Disconnect { client_id } => {
                        if let Some(ref disconnect) = callbacks.disconnect {
                            let disconnect = Arc::clone(disconnect);
                            tokio::spawn(async move {
                                (*disconnect)(client_id).await;
                            });
                        }
                    }
                    ServerEventRawSafe::Receive { client_id, data } => {
                        if let Some(ref receive) = callbacks.receive {
                            let receive = Arc::clone(receive);
                            tokio::spawn(async move {
                                let data = data.deserialize();
                                (*receive)(client_id, data).await;
                            });
                        }
                    }
                    ServerEventRawSafe::Stop => {
                        if let Some(ref stop) = callbacks.stop {
                            let stop = Arc::clone(stop);
                            tokio::spawn(async move {
                                (*stop)().await;
                            });
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
    S: Serialize + 'static,
    R: DeserializeOwned + 'static,
    H: ServerEventHandler<R> + 'static,
{
    /// Starts the server. This is effectively identical to [`Server::start`].
    ///
    /// # Errors
    ///
    /// The set of errors that can occur are identical to that of
    /// [`Server::start`].
    #[allow(clippy::future_not_send)]
    pub async fn start<A>(self, addr: A) -> io::Result<ServerHandle<S>>
    where
        A: ToSocketAddrs,
    {
        let (server, mut server_events) = Server::<S, R>::start(addr).await?;
        let handler = Arc::new(self.event_reporting.0.handler);

        tokio::spawn(async move {
            while let Ok(event) = server_events.next_raw().await {
                match event {
                    ServerEventRawSafe::Connect { client_id } => {
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move {
                            handler.on_connect(client_id).await;
                        });
                    }
                    ServerEventRawSafe::Disconnect { client_id } => {
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move {
                            handler.on_disconnect(client_id).await;
                        });
                    }
                    ServerEventRawSafe::Receive { client_id, data } => {
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move {
                            let data = data.deserialize();
                            handler.on_receive(client_id, data).await;
                        });
                    }
                    ServerEventRawSafe::Stop => {
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
    S: Serialize + 'static,
    R: DeserializeOwned + 'static,
{
    /// Starts the server. This is effectively identical to [`Server::start`].
    ///
    /// # Errors
    ///
    /// The set of errors that can occur are identical to that of
    /// [`Server::start`].
    #[allow(clippy::future_not_send)]
    pub async fn start<A>(self, addr: A) -> io::Result<(ServerHandle<S>, ServerEventStream<R>)>
    where
        A: ToSocketAddrs,
    {
        Server::<S, R>::start(addr).await
    }
}

/// A command sent from the server handle to the background server task.
pub enum ServerCommand {
    /// Stop the server.
    Stop,
    /// Send data to a client.
    Send {
        /// The ID of the client to send the data to.
        client_id: usize,
        /// The data to send.
        data: Vec<u8>,
    },
    /// Send data to all clients.
    SendAll {
        /// The data to send.
        data: Vec<u8>,
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
///     while let Ok(event) = server_events.next().await {
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
    R: DeserializeOwned + 'static,
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

/// Identical to `ServerEvent`, but with the received data in serialized form.
#[derive(Debug, Clone)]
enum ServerEventRaw {
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
        data: Vec<u8>,
    },
    /// Server stopped.
    Stop,
}

impl ServerEventRaw {
    /// Deserializes this instance into a `ServerEvent`.
    fn deserialize<R>(&self) -> io::Result<ServerEvent<R>>
    where
        R: DeserializeOwned + 'static,
    {
        match self {
            Self::Connect { client_id } => Ok(ServerEvent::Connect {
                client_id: *client_id,
            }),
            Self::Disconnect { client_id } => Ok(ServerEvent::Disconnect {
                client_id: *client_id,
            }),
            Self::Receive { client_id, data } => match serde_json::from_slice(data) {
                Ok(data) => Ok(ServerEvent::Receive {
                    client_id: *client_id,
                    data,
                }),
                Err(err) => generic_io_error(err),
            },
            Self::Stop => Ok(ServerEvent::Stop),
        }
    }
}

/// The serialized data component of a server receive event. The data is
/// guaranteed to be deserializable into an instance of `R`.
#[derive(Debug, Clone)]
struct ServerEventRawSafeData<R>
where
    R: DeserializeOwned + 'static,
{
    /// The raw data.
    data: Vec<u8>,
    /// Phantom marker for `R`.
    marker: PhantomData<fn() -> R>,
}

/// Identical to `ServerEventRaw`, but with the guarantee that the data can be
/// deserialized into an instance of `R`.
#[derive(Debug, Clone)]
enum ServerEventRawSafe<R>
where
    R: DeserializeOwned + 'static,
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
        data: ServerEventRawSafeData<R>,
    },
    /// Server stopped.
    Stop,
}

impl<R> TryFrom<ServerEventRaw> for ServerEventRawSafe<R>
where
    R: DeserializeOwned + 'static,
{
    type Error = io::Error;

    fn try_from(value: ServerEventRaw) -> std::result::Result<Self, Self::Error> {
        value.deserialize::<R>()?;

        Ok(match value {
            ServerEventRaw::Connect { client_id } => Self::Connect { client_id },
            ServerEventRaw::Disconnect { client_id } => Self::Disconnect { client_id },
            ServerEventRaw::Receive { client_id, data } => Self::Receive {
                client_id,
                data: ServerEventRawSafeData {
                    data,
                    marker: PhantomData,
                },
            },
            ServerEventRaw::Stop => Self::Stop,
        })
    }
}

impl<R> ServerEventRawSafeData<R>
where
    R: DeserializeOwned + 'static,
{
    /// Deserialize the raw data into an instance of `R`. This is guaranteed to
    /// succeed.
    fn deserialize(&self) -> R {
        serde_json::from_slice(&self.data).unwrap()
    }
}

impl<R> ServerEventRawSafe<R>
where
    R: DeserializeOwned + 'static,
{
    /// Deserializes this instance into a `ServerEvent`.
    #[allow(dead_code)]
    fn deserialize(&self) -> ServerEvent<R> {
        match self {
            Self::Connect { client_id } => ServerEvent::Connect {
                client_id: *client_id,
            },
            Self::Disconnect { client_id } => ServerEvent::Disconnect {
                client_id: *client_id,
            },
            Self::Receive { client_id, data } => ServerEvent::Receive {
                client_id: *client_id,
                data: data.deserialize(),
            },
            Self::Stop => ServerEvent::Stop,
        }
    }
}

/// An asynchronous stream of server events.
pub struct ServerEventStream<R>
where
    R: DeserializeOwned + 'static,
{
    /// The event receiver channel.
    event_receiver: Receiver<ServerEventRaw>,
    /// Phantom marker for `R`.
    marker: PhantomData<fn() -> R>,
}

impl<R> ServerEventStream<R>
where
    R: DeserializeOwned + 'static,
{
    /// Consumes and returns the next value in the stream.
    ///
    /// # Errors
    ///
    /// This will return an error if the stream is closed, or if there was an
    /// error while deserializing data received.
    pub async fn next(&mut self) -> io::Result<ServerEvent<R>> {
        match self.event_receiver.recv().await {
            Some(serialized_event) => serialized_event.deserialize(),
            None => generic_io_error("event stream is closed"),
        }
    }

    /// Identical to `next`, but doesn't deserialize the event. It does,
    /// however, validate that the event can be deserialized without error.
    async fn next_raw(&mut self) -> io::Result<ServerEventRawSafe<R>> {
        match self.event_receiver.recv().await {
            Some(serialized_event) => serialized_event.try_into(),
            None => generic_io_error("event stream is closed"),
        }
    }
}

/// A handle to the server.
pub struct ServerHandle<S>
where
    S: Serialize + 'static,
{
    /// The channel through which commands can be sent to the background task.
    server_command_sender: CommandChannelSender<ServerCommand, ServerCommandReturn>,
    /// The handle to the background task.
    server_task_handle: JoinHandle<io::Result<()>>,
    /// Phantom marker for `S`.
    marker: PhantomData<fn() -> S>,
}

impl<S> ServerHandle<S>
where
    S: Serialize + 'static,
{
    /// Stop the server, disconnect all clients, and shut down all network
    /// interfaces.
    ///
    /// Returns a result of the error variant if an error occurred while
    /// disconnecting clients.
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
    ///     while let Ok(event) = server_events.next().await {
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
    ///
    /// # Errors
    ///
    /// This will return an error if the server socket has already closed, or if
    /// the underlying server loop returned an error.
    #[allow(clippy::missing_panics_doc)]
    pub async fn stop(mut self) -> io::Result<()> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::Stop)
            .await?;
        // `unwrap` is allowed, as an error is returned only when the underlying
        // task panics, which it never should
        self.server_task_handle.await.unwrap()?;
        unwrap_enum!(value, ServerCommandReturn::Stop)
    }

    /// Send data to a client.
    ///
    /// - `client_id`: the ID of the client to send the data to.
    /// - `data`: the data to send.
    ///
    /// Returns a result of the error variant if an error occurred while
    /// sending.
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
    ///     while let Ok(event) = server_events.next().await {
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
    ///
    /// # Errors
    ///
    /// This will return an error if the server socket has closed, or if data
    /// serialization fails.
    #[allow(clippy::future_not_send)]
    pub async fn send(&mut self, client_id: usize, data: S) -> io::Result<()> {
        let data_serialized = into_generic_io_result(serde_json::to_vec(&data))?;
        let value = self
            .server_command_sender
            .send_command(ServerCommand::Send {
                client_id,
                data: data_serialized,
            })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::Send)
    }

    /// Send data to all clients.
    ///
    /// - `data`: the data to send.
    ///
    /// Returns a result of the error variant if an error occurred while
    /// sending.
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
    ///     while let Ok(event) = server_events.next().await {
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
    ///
    /// # Errors
    ///
    /// This will return an error if the server socket has closed, or if data
    /// serialization fails.
    #[allow(clippy::future_not_send)]
    pub async fn send_all(&mut self, data: S) -> io::Result<()> {
        let data_serialized = into_generic_io_result(serde_json::to_vec(&data))?;
        let value = self
            .server_command_sender
            .send_command(ServerCommand::SendAll {
                data: data_serialized,
            })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::SendAll)
    }

    /// Get the address the server is listening on.
    ///
    /// Returns a result containing the address the server is listening on, or
    /// the error variant if an error occurred.
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
    ///
    /// # Errors
    ///
    /// This will return an error if the server socket has closed.
    pub async fn get_addr(&mut self) -> io::Result<SocketAddr> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::GetAddr)
            .await?;
        unwrap_enum!(value, ServerCommandReturn::GetAddr)
    }

    /// Get the address of a connected client.
    ///
    /// - `client_id`: the ID of the client.
    ///
    /// Returns a result containing the address of the client, or the error
    /// variant if the client ID is invalid.
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
    ///     while let Ok(event) = server_events.next().await {
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
    /// ```
    ///
    /// # Errors
    ///
    /// This will return an error if the server socket has closed, or if the
    /// client ID is invalid.
    pub async fn get_client_addr(&mut self, client_id: usize) -> io::Result<SocketAddr> {
        let value = self
            .server_command_sender
            .send_command(ServerCommand::GetClientAddr { client_id })
            .await?;
        unwrap_enum!(value, ServerCommandReturn::GetClientAddr)
    }

    /// Disconnect a client from the server.
    ///
    /// - `client_id`: the ID of the client.
    ///
    /// Returns a result of the error variant if an error occurred while
    /// disconnecting the client, or if the client ID is invalid.
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
    ///     while let Ok(event) = server_events.next().await {
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
    ///
    /// # Errors
    ///
    /// This will return an error if the server socket has closed, or if the
    /// client ID is invalid.
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
/// Both types must be serializable in order to be sent through the socket. When
/// creating clients, the types should be swapped, since the server's send type will be the client's receive type and vice versa.
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
///     while let Ok(event) = server_events.next().await {
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
    S: Serialize + 'static,
    R: DeserializeOwned + 'static,
{
    /// Phantom marker for `S` and `R`.
    marker: PhantomData<fn() -> (S, R)>,
}

impl Server<(), ()> {
    /// Constructs a server builder. Use this for a clearer, more explicit,
    /// and more featureful server configuration. See [`ServerBuilder`] for
    /// more information.
    pub const fn builder(
    ) -> ServerBuilder<ServerSendingUnknown, ServerReceivingUnknown, ServerEventReportingUnknown>
    {
        ServerBuilder::new()
    }
}

impl<S, R> Server<S, R>
where
    S: Serialize + 'static,
    R: DeserializeOwned + 'static,
{
    /// Start a socket server.
    ///
    /// - `addr`: the address for the server to listen on.
    ///
    /// Returns a result containing a handle to the server and a channel from
    /// which to receive server events, or the error variant if an error
    /// occurred while starting the server.
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
    /// Neither the server handle nor the event receiver should be dropped until
    /// the server has been stopped. Prematurely dropping either one can cause
    /// unintended behavior.
    ///
    /// # Errors
    ///
    /// This will return an error if a TCP listener cannot be bound to the
    /// provided address.
    #[allow(clippy::future_not_send)]
    pub async fn start<A>(addr: A) -> io::Result<(ServerHandle<S>, ServerEventStream<R>)>
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
            marker: PhantomData,
        };

        // Create an event stream for the server
        let server_event_stream = ServerEventStream {
            event_receiver: server_event_receiver,
            marker: PhantomData,
        };

        Ok((server_handle, server_event_stream))
    }
}

/// The server client loop. Handles received data and commands.
#[allow(clippy::too_many_lines)]
async fn server_client_loop(
    client_id: usize,
    mut socket: TcpStream,
    server_client_event_sender: Sender<ServerEventRaw>,
    mut client_command_receiver: CommandChannelReceiver<
        ServerClientCommand,
        ServerClientCommandReturn,
    >,
) -> io::Result<()> {
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
        socket.read(&mut aes_key_size_buffer[..])
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

    // Read the AES key portion from the client socket, returning an error if
    // the socket could not be read
    let n_aes_key = data_read_timeout! {
        socket.read(&mut aes_key_buffer[..])
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

    // Buffer in which to receive the size portion of a message
    let mut size_buffer = [0; LEN_SIZE];

    // Client loop
    loop {
        // Await messages from the client
        // and commands from the background server task
        tokio::select! {
            // Read the size portion from the client socket
            read_value = socket.read(&mut size_buffer[..]) => {
                // Return an error if the socket could not be read
                let n_size = read_value?;

                // If there were no bytes read, or if there were fewer bytes
                // read than there should have been, close the socket
                if n_size != LEN_SIZE {
                    socket.shutdown().await?;
                    break;
                };

                // Decode the size portion of the message
                let encrypted_data_size = decode_message_size(&size_buffer);
                // Initialize the buffer for the data portion of the message
                let mut encrypted_data_buffer = vec![0; encrypted_data_size];

                // Read the data portion from the client socket, returning an
                // error if the socket could not be read
                let n_data = data_read_timeout! {
                    socket.read_exact(&mut encrypted_data_buffer[..])
                }??;

                // If there were no bytes read, or if there were fewer bytes
                // read than there should have been, close the socket
                if n_data != encrypted_data_size {
                    socket.shutdown().await?;
                    break;
                }

                // Decrypt the data
                let data_serialized = match aes_decrypt(aes_key, encrypted_data_buffer.into()).await {
                    Ok(val) => Ok(val),
                    Err(e) => generic_io_error(format!("failed to decrypt data: {e}")),
                }?;

                // Send an event to note that a piece of data has been received from
                // a client
                if let Err(_e) = server_client_event_sender.send(ServerEventRaw::Receive { client_id, data: data_serialized }).await {
                    // Sending failed, disconnect the client
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
                                    // Extend the buffer to contain the payload
                                    // size
                                    buffer.extend_from_slice(&size_buffer);
                                    // Extend the buffer to contain the payload
                                    // data
                                    buffer.extend(&encrypted_data_buffer);

                                    // Write the data to the client socket
                                    let n = break_on_err!(socket.write(&buffer).await, 'val);
                                    // Flush the stream
                                    break_on_err!(socket.flush().await, 'val);

                                    // If there were no bytes written, or if
                                    // there were fewer bytes written than there
                                    // should have been, close the socket
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

                                // Return the status of the remove operation,
                                // ignoring failures, since a failure indicates
                                // that the client has probably already
                                // disconnected
                                _ = client_command_receiver.command_return(ServerClientCommandReturn::Remove(value)).await;

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
fn server_client_handler(
    client_id: usize,
    socket: TcpStream,
    server_client_event_sender: Sender<ServerEventRaw>,
    client_cleanup_sender: Sender<usize>,
) -> (
    CommandChannelSender<ServerClientCommand, ServerClientCommandReturn>,
    JoinHandle<io::Result<()>>,
) {
    // Channels for sending commands from the background server task to a background client task
    let (client_command_sender, client_command_receiver) = command_channel();

    // Start a background client task, saving the join handle for when the
    // server is stopped
    let client_task_handle = tokio::spawn(async move {
        let res = server_client_loop(
            client_id,
            socket,
            server_client_event_sender,
            client_command_receiver,
        )
        .await;

        // Tell the server to clean up after the client, ignoring failures,
        // since a failure indicates that the server has probably closed
        _ = client_cleanup_sender.send(client_id).await;

        res
    });

    (client_command_sender, client_task_handle)
}

/// The server loop. Handles incoming connections and commands.
#[allow(clippy::too_many_lines)]
async fn server_loop(
    listener: TcpListener,
    server_event_sender: Sender<ServerEventRaw>,
    mut server_command_receiver: CommandChannelReceiver<ServerCommand, ServerCommandReturn>,
    client_command_senders: &mut HashMap<
        usize,
        CommandChannelSender<ServerClientCommand, ServerClientCommandReturn>,
    >,
    client_join_handles: &mut HashMap<usize, JoinHandle<io::Result<()>>>,
) -> io::Result<()> {
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
                // Clone the event sender so the background client tasks can
                // send events
                let server_client_event_sender = server_event_sender.clone();
                // Clone the client cleanup sender to the background client
                // tasks can be cleaned up properly
                let client_cleanup_sender = server_client_cleanup_sender.clone();

                // Handle the new connection
                let (client_command_sender, client_task_handle) = server_client_handler(client_id, socket, server_client_event_sender, client_cleanup_sender);
                // Keep track of client command senders
                client_command_senders.insert(client_id, client_command_sender);
                // Keep track of client task handles
                client_join_handles.insert(client_id, client_task_handle);

                // Send an event to note that a client has connected
                // successfully
                if let Err(_e) = server_event_sender
                    .send(ServerEventRaw::Connect { client_id })
                    .await
                {
                    // Server is probably closed
                    break;
                }
            },
            // Process a command from the server handle
            command_value = server_command_receiver.recv_command() => {
                // Handle the command, or lack thereof if the channel is closed
                match command_value {
                    Ok(command) => {
                        match command {
                            ServerCommand::Stop => {
                                // If a command fails to send, the server has
                                // already closed, and the error can be ignored.
                                // It should be noted that this is not where the
                                // stop method actually returns its `Result`.
                                // This immediately returns with an `Ok` status.
                                // The real return value is the `Result`
                                // returned from the server task join handle.
                                _ = server_command_receiver.command_return(ServerCommandReturn::Stop(Ok(()))).await;

                                // Break the server loop, the clients will be
                                // disconnected before the task ends
                                break;
                            },
                            ServerCommand::Send { client_id, data } => {
                                let value = match client_command_senders.get_mut(&client_id) {
                                    Some(client_command_sender) => {
                                        // Turn `Vec<u8>` into `Arc<[u8]>`,
                                        // making it more easily shareable
                                        let shareable_data = Arc::<[u8]>::from(data);

                                        match client_command_sender.send_command(ServerClientCommand::Send { data: shareable_data }).await {
                                            Ok(return_value) => unwrap_enum!(return_value, ServerClientCommandReturn::Send),
                                            Err(_e) => {
                                                // The channel is closed, and
                                                // the client has probably been
                                                // disconnected, so the error
                                                // can be ignored
                                                Ok(())
                                            },
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
                                    // Turn `Vec<u8>` into `Arc<[u8]>`, making
                                    // it more easily shareable
                                    let shareable_data = Arc::<[u8]>::from(data);

                                    let send_futures = client_command_senders.iter_mut().map(|(_client_id, client_command_sender)| async {
                                        match client_command_sender.send_command(ServerClientCommand::Send { data: Arc::clone(&shareable_data) }).await {
                                            Ok(return_value) => unwrap_enum!(return_value, ServerClientCommandReturn::Send),
                                            Err(_e) => {
                                                // The channel is closed, and
                                                // the client has probably been
                                                // disconnected, so the error
                                                // can be ignored
                                                Ok(())
                                            }
                                        }
                                    });

                                    let resolved = futures::future::join_all(send_futures).await;
                                    resolved.into_iter().collect::<io::Result<Vec<_>>>().map(|_| ())
                                };

                                // If a command fails to send, the client has
                                // probably disconnected, and the error can be
                                // ignored
                                _ = server_command_receiver.command_return(ServerCommandReturn::SendAll(value)).await;
                            },
                            ServerCommand::GetAddr => {
                                // Get the server listener's address
                                let addr = listener.local_addr();

                                // If a command fails to send, the client has
                                // probably disconnected, and the error can be
                                // ignored
                                _ = server_command_receiver.command_return(ServerCommandReturn::GetAddr(addr)).await;
                            },
                            ServerCommand::GetClientAddr { client_id } => {
                                let value = match client_command_senders.get_mut(&client_id) {
                                    Some(client_command_sender) => match client_command_sender.send_command(ServerClientCommand::GetAddr).await {
                                        Ok(return_value) => unwrap_enum!(return_value, ServerClientCommandReturn::GetAddr),
                                        Err(_e) => {
                                            // The channel is closed, and the
                                            // client has probably been
                                            // disconnected, so the error can be
                                            // treated as an invalid client
                                            // error
                                            generic_io_error("invalid client")
                                        },
                                    },
                                    None => generic_io_error("invalid client"),
                                };

                                // If a command fails to send, the client has
                                // probably disconnected, and the error can be
                                // ignored
                                _ = server_command_receiver.command_return(ServerCommandReturn::GetClientAddr(value)).await;
                            },
                            ServerCommand::RemoveClient { client_id } => {
                                let value = match client_command_senders.get_mut(&client_id) {
                                    Some(client_command_sender) => match client_command_sender.send_command(ServerClientCommand::Remove).await {
                                        Ok(return_value) => unwrap_enum!(return_value, ServerClientCommandReturn::Remove),
                                        Err(_e) => {
                                            // The channel is closed, and the
                                            // client has probably been
                                            // disconnected, so the error can be
                                            // ignored
                                            Ok(())
                                        },
                                    },
                                    None => generic_io_error("invalid client"),
                                };

                                // If a command fails to send, the client has
                                // probably disconnected already, and the error
                                // can be ignored
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
                        // Remove the client's command sender, which will be
                        // dropped after this block ends
                        client_command_senders.remove(&client_id);

                        // Remove the client's join handle
                        if let Some(handle) = client_join_handles.remove(&client_id) {
                            // Join the client's handle
                            if let Err(e) = handle.await.unwrap() {
                                if cfg!(test) {
                                    // If testing, fail
                                    Err(e)?;
                                } else {
                                    // If not testing, ignore client handler
                                    // errors
                                }
                            }
                        }

                        // Send an event to note that a client has disconnected
                        if let Err(_e) = server_event_sender.send(ServerEventRaw::Disconnect { client_id }).await {
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
async fn server_handler(
    listener: TcpListener,
    server_event_sender: Sender<ServerEventRaw>,
    server_command_receiver: CommandChannelReceiver<ServerCommand, ServerCommandReturn>,
) -> io::Result<()> {
    // Collection of channels for sending commands from the background server
    // task to a background client task
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
            // If a command fails to send, the client has probably disconnected
            // already, and the error can be ignored
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
                Err(e)?;
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
    _ = server_event_sender.send(ServerEventRaw::Stop).await;

    // Return server loop result
    server_exit
}
