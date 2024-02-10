//! Protocol client implementation.

use super::command_channel::*;
use super::event_stream::*;
use super::timeout::*;
use crate::crypto::*;
use crate::util::*;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use serde::{de::DeserializeOwned, ser::Serialize};
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::mpsc::{channel, Sender};
use tokio::task::JoinHandle;

/// Configuration for a client's event callbacks.
///
/// # Events
///
/// There are two events for which callbacks can be registered:
///
///  - `receive`
///  - `disconnect`
///
/// Both callbacks are optional, and can be registered for any combination of
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
/// let client = Client::builder()
///     .sending::<String>()
///     .receiving::<usize>()
///     .with_event_callbacks(
///         ClientEventCallbacks::new()
///             .on_receive(move |data| async move {
///                 // some async operation...
///                 println!("Received data from server: {}", data);
///             })
///             .on_disconnect(move || async move {
///                 // some async operation...
///                 println!("Disconnected from server");
///             })
///     )
///     .connect(("127.0.0.1", 29275))
///     .await
///     .unwrap();
/// # }
/// ```
#[allow(clippy::type_complexity)]
pub struct ClientEventCallbacks<R>
where
    R: DeserializeOwned + Send + 'static,
{
    /// The `receive` event callback.
    receive: Option<Box<dyn Fn(R) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>>,
    /// The `disconnect` event callback.
    disconnect: Option<Box<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>>,
}

impl<R> ClientEventCallbacks<R>
where
    R: DeserializeOwned + Send + 'static,
{
    /// Creates a new client event callbacks configuration with all callbacks
    /// empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a callback on the `receive` event.
    pub fn on_receive<C, F>(mut self, callback: C) -> Self
    where
        C: Fn(R) -> F + Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        self.receive = Some(Box::new(move |data| Box::pin((callback)(data))));
        self
    }

    /// Registers a callback on the `disconnect` event.
    pub fn on_disconnect<C, F>(mut self, callback: C) -> Self
    where
        C: Fn() -> F + Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        self.disconnect = Some(Box::new(move || Box::pin((callback)())));
        self
    }
}

impl<R> Default for ClientEventCallbacks<R>
where
    R: DeserializeOwned + Send + 'static,
{
    fn default() -> Self {
        Self {
            receive: None,
            disconnect: None,
        }
    }
}

/// An event handling trait for the client.
///
/// # Events
///
/// There are two events for which methods can be implemented:
///
///  - `receive`
///  - `disconnect`
///
/// Both method implementations are optional, and can be registered for any
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
/// struct MyClientHandler;
///
/// impl ClientEventHandler<usize> for MyClientHandler {
///     async fn on_receive(&self, data: usize) {
///         // some async operation...
///         println!("Received data from server: {}", data);
///     }
///
///     async fn on_disconnect(&self) {
///         // some async operation...
///         println!("Disconnected from server");
///     }
/// }
/// # }
/// ```
pub trait ClientEventHandler<R>
where
    Self: Send + Sync,
    R: DeserializeOwned + Send + 'static,
{
    /// Handles the `receive` event.
    #[allow(unused_variables)]
    fn on_receive(&self, data: R) -> impl Future<Output = ()> + Send {
        async {}
    }

    /// Handles the `disconnect` event.
    fn on_disconnect(&self) -> impl Future<Output = ()> + Send {
        async {}
    }
}

/// Unknown client sending type.
pub struct ClientSendingUnknown;

/// Known client sending type, stored as the type parameter `S`.
pub struct ClientSending<S>(PhantomData<S>)
where
    S: Serialize + Send + 'static;

/// A client sending marker trait.
pub(crate) trait ClientSendingConfig {}

impl ClientSendingConfig for ClientSendingUnknown {}

impl<S> ClientSendingConfig for ClientSending<S> where S: Serialize + Send + 'static {}

/// Unknown client receiving type.
pub struct ClientReceivingUnknown;

/// Known client receiving type, stored as the type parameter `R`.
pub struct ClientReceiving<R>(PhantomData<R>)
where
    R: DeserializeOwned + Send + 'static;

/// A client receiving marker trait.
pub(crate) trait ClientReceivingConfig {}

impl ClientReceivingConfig for ClientReceivingUnknown {}

impl<R> ClientReceivingConfig for ClientReceiving<R> where R: DeserializeOwned + Send + 'static {}

/// Unknown client event reporting type.
pub struct ClientEventReportingUnknown;

/// Known client event reporting type, stored as the type parameter `E`.
pub struct ClientEventReporting<E>(E);

/// Client event reporting via callbacks.
pub struct ClientEventReportingCallbacks<R>(ClientEventCallbacks<R>)
where
    R: DeserializeOwned + Send + 'static;

/// Client event reporting via an event handler.
pub struct ClientEventReportingHandler<R, H>
where
    R: DeserializeOwned + Send + 'static,
    H: ClientEventHandler<R>,
{
    /// The event handler instance.
    handler: H,
    /// Phantom `R` owner.
    phantom_receive: PhantomData<R>,
}

/// Client event reporting via a channel.
pub struct ClientEventReportingChannel;

/// A client event reporting marker trait.
pub(crate) trait ClientEventReportingConfig {}

impl ClientEventReportingConfig for ClientEventReportingUnknown {}

impl<R> ClientEventReportingConfig for ClientEventReporting<ClientEventReportingCallbacks<R>> where
    R: DeserializeOwned + Send + 'static
{
}

impl<R, H> ClientEventReportingConfig for ClientEventReporting<ClientEventReportingHandler<R, H>>
where
    R: DeserializeOwned + Send + 'static,
    H: ClientEventHandler<R>,
{
}

impl ClientEventReportingConfig for ClientEventReporting<ClientEventReportingChannel> {}

/// A builder for the [`Client`].
///
/// An instance of this can be constructed using `ClientBuilder::new()` or
/// `Client::builder()`. The configuration information exists primarily at the
/// type-level, so it is impossible to misconfigure this.
///
/// This method of configuration is technically not necessary, but it is far
/// clearer and more explicit than simply configuring the `Client` type. Plus,
/// it provides additional ways of detecting events.
///
/// # Configuration
///
/// To configure the client, first provide the types that will be sent and
/// received through the client using the `.sending::<...>()` and
/// `.receiving::<...>()` methods. Then specify the way in which events will
/// be detected. There are three methods of receiving events:
///
/// - via callback functions (`.with_event_callbacks(...)`)
/// - via implementation of a handler trait (`.with_event_handler(...)`)
/// - via a channel (`.with_event_channel()`)
///
/// The channel method is the most versatile, hence why it's the `Client`'s
/// default implementation. The other methods are provided to support a
/// greater variety of program architectures.
///
/// Once configured, the `.connect(...)` method, which is effectively
/// identical to the `Client::connect(...)` method, can be called to connect
/// to the server.
///
/// # Example
///
/// ```no_run
/// # use rustdtp::*;
///
/// # #[tokio::main]
/// # async fn main() {
/// let (client, client_events) = Client::builder()
///     .sending::<String>()
///     .receiving::<usize>()
///     .with_event_channel()
///     .connect(("127.0.0.1", 29275))
///     .await
///     .unwrap();
/// # }
/// ```
#[allow(private_bounds)]
pub struct ClientBuilder<SC, RC, EC>
where
    SC: ClientSendingConfig,
    RC: ClientReceivingConfig,
    EC: ClientEventReportingConfig,
{
    /// Phantom `SC` owner.
    phantom_send: PhantomData<SC>,
    /// Phantom `RC` owner.
    phantom_receive: PhantomData<RC>,
    /// The event reporting configuration.
    event_reporting: EC,
}

impl ClientBuilder<ClientSendingUnknown, ClientReceivingUnknown, ClientEventReportingUnknown> {
    /// Creates a new client builder.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default
    for ClientBuilder<ClientSendingUnknown, ClientReceivingUnknown, ClientEventReportingUnknown>
{
    fn default() -> Self {
        ClientBuilder {
            phantom_send: PhantomData,
            phantom_receive: PhantomData,
            event_reporting: ClientEventReportingUnknown,
        }
    }
}

#[allow(private_bounds)]
impl<RC, EC> ClientBuilder<ClientSendingUnknown, RC, EC>
where
    RC: ClientReceivingConfig,
    EC: ClientEventReportingConfig,
{
    /// Configures the type of data the client intends to send to the server.
    pub fn sending<S>(self) -> ClientBuilder<ClientSending<S>, RC, EC>
    where
        S: Serialize + Send + 'static,
    {
        ClientBuilder {
            phantom_send: PhantomData,
            phantom_receive: PhantomData,
            event_reporting: self.event_reporting,
        }
    }
}

#[allow(private_bounds)]
impl<SC, EC> ClientBuilder<SC, ClientReceivingUnknown, EC>
where
    SC: ClientSendingConfig,
    EC: ClientEventReportingConfig,
{
    /// Configures the type of data the client intends to receive from the
    /// server.
    pub fn receiving<R>(self) -> ClientBuilder<SC, ClientReceiving<R>, EC>
    where
        R: DeserializeOwned + Send + 'static,
    {
        ClientBuilder {
            phantom_send: PhantomData,
            phantom_receive: PhantomData,
            event_reporting: self.event_reporting,
        }
    }
}

#[allow(private_bounds)]
impl<S, R> ClientBuilder<ClientSending<S>, ClientReceiving<R>, ClientEventReportingUnknown>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    /// Configures the client to receive events via callbacks.
    ///
    /// Using callbacks is typically considered an anti-pattern in Rust, so
    /// this should only be used if it makes sense in the context of the
    /// design of the code utilizing this API.
    ///
    /// See [`ClientEventCallbacks`] for more information and examples.
    pub fn with_event_callbacks(
        self,
        callbacks: ClientEventCallbacks<R>,
    ) -> ClientBuilder<
        ClientSending<S>,
        ClientReceiving<R>,
        ClientEventReporting<ClientEventReportingCallbacks<R>>,
    > {
        ClientBuilder {
            phantom_send: PhantomData,
            phantom_receive: PhantomData,
            event_reporting: ClientEventReporting(ClientEventReportingCallbacks(callbacks)),
        }
    }

    /// Configures the client to receive events via a trait implementation.
    ///
    /// This provides an approach to event handling that closely aligns with
    /// object-oriented practices.
    ///
    /// See [`ClientEventHandler`] for more information and examples.
    pub fn with_event_handler<H>(
        self,
        handler: H,
    ) -> ClientBuilder<
        ClientSending<S>,
        ClientReceiving<R>,
        ClientEventReporting<ClientEventReportingHandler<R, H>>,
    >
    where
        H: ClientEventHandler<R>,
    {
        ClientBuilder {
            phantom_send: PhantomData,
            phantom_receive: PhantomData,
            event_reporting: ClientEventReporting(ClientEventReportingHandler {
                handler,
                phantom_receive: PhantomData,
            }),
        }
    }

    /// Configures the client to receive events via a channel.
    ///
    /// This is the most versatile event handling strategy. In fact, all other
    /// event handling options use this implementation under the hood.
    /// Because of its flexibility, this will typically be the desired
    /// approach.
    pub fn with_event_channel(
        self,
    ) -> ClientBuilder<
        ClientSending<S>,
        ClientReceiving<R>,
        ClientEventReporting<ClientEventReportingChannel>,
    > {
        ClientBuilder {
            phantom_send: PhantomData,
            phantom_receive: PhantomData,
            event_reporting: ClientEventReporting(ClientEventReportingChannel),
        }
    }
}

impl<S, R>
    ClientBuilder<
        ClientSending<S>,
        ClientReceiving<R>,
        ClientEventReporting<ClientEventReportingCallbacks<R>>,
    >
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    /// Connects to a server. This is effectively identical to
    /// `Client::connect(...)`.
    pub async fn connect<A>(self, addr: A) -> io::Result<ClientHandle<S>>
    where
        A: ToSocketAddrs,
    {
        let (client, mut client_events) = Client::<S, R>::connect(addr).await?;
        let callbacks = self.event_reporting.0 .0;

        tokio::spawn(async move {
            while let Some(event) = client_events.next().await {
                match event {
                    ClientEvent::Receive { data } => {
                        if let Some(ref receive) = callbacks.receive {
                            tokio::spawn((*receive)(data));
                        }
                    }
                    ClientEvent::Disconnect => {
                        if let Some(ref disconnect) = callbacks.disconnect {
                            tokio::spawn((*disconnect)());
                        }
                    }
                }
            }
        });

        Ok(client)
    }
}

impl<S, R, H>
    ClientBuilder<
        ClientSending<S>,
        ClientReceiving<R>,
        ClientEventReporting<ClientEventReportingHandler<R, H>>,
    >
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
    H: ClientEventHandler<R> + 'static,
{
    /// Connects to a server. This is effectively identical to
    /// `Client::connect(...)`.
    pub async fn connect<A>(self, addr: A) -> io::Result<ClientHandle<S>>
    where
        A: ToSocketAddrs,
    {
        let (client, mut client_events) = Client::<S, R>::connect(addr).await?;
        let handler = Arc::new(self.event_reporting.0.handler);

        tokio::spawn(async move {
            while let Some(event) = client_events.next().await {
                match event {
                    ClientEvent::Receive { data } => {
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move {
                            handler.on_receive(data).await;
                        });
                    }
                    ClientEvent::Disconnect => {
                        let handler = Arc::clone(&handler);
                        tokio::spawn(async move {
                            handler.on_disconnect().await;
                        });
                    }
                }
            }
        });

        Ok(client)
    }
}

impl<S, R>
    ClientBuilder<
        ClientSending<S>,
        ClientReceiving<R>,
        ClientEventReporting<ClientEventReportingChannel>,
    >
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    /// Connects to a server. This is effectively identical to
    /// `Client::connect(...)`.
    pub async fn connect<A>(
        self,
        addr: A,
    ) -> io::Result<(ClientHandle<S>, EventStream<ClientEvent<R>>)>
    where
        A: ToSocketAddrs,
    {
        Client::<S, R>::connect(addr).await
    }
}

/// A command sent from the client handle to the background client task.
pub enum ClientCommand<S>
where
    S: Serialize + Send + 'static,
{
    /// Disconnect from the server.
    Disconnect,
    /// Send data to the server.
    Send {
        /// The data to send.
        data: S,
    },
    /// Get the local client address.
    GetAddr,
    /// Get the server's address.
    GetServerAddr,
}

/// The return value of a command executed on the background client task.
pub enum ClientCommandReturn {
    /// Disconnect return value.
    Disconnect(io::Result<()>),
    /// Sent data return value.
    Send(io::Result<()>),
    /// Local client address return value.
    GetAddr(io::Result<SocketAddr>),
    /// Server address return value.
    GetServerAddr(io::Result<SocketAddr>),
}

/// An event from the client.
///
/// ```no_run
/// use rustdtp::*;
///
/// #[tokio::main]
/// async fn main() {
///     // Create the client
///     let (mut client, mut client_events) = Client::builder()
///         .sending::<()>()
///         .receiving::<String>()
///         .with_event_channel()
///         .connect(("127.0.0.1", 29275))
///         .await
///         .unwrap();
///
///     // Iterate over events
///     while let Some(event) = client_events.next().await {
///         match event {
///             ClientEvent::Receive { data } => {
///                 println!("Server sent: {}", data);
///             }
///             ClientEvent::Disconnect => {
///                 // No more events will be sent, and the loop will end
///                 println!("Client disconnected");
///             }
///         }
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub enum ClientEvent<R>
where
    R: DeserializeOwned + Send + 'static,
{
    /// Data received from the server.
    Receive {
        /// The data itself.
        data: R,
    },
    /// Disconnected from the server.
    Disconnect,
}

/// A handle to the client.
pub struct ClientHandle<S>
where
    S: Serialize + Send + 'static,
{
    /// The channel through which commands can be sent to the background task.
    client_command_sender: CommandChannelSender<ClientCommand<S>, ClientCommandReturn>,
    /// The handle to the background task.
    client_task_handle: JoinHandle<io::Result<()>>,
}

impl<S> ClientHandle<S>
where
    S: Serialize + Send + 'static,
{
    /// Disconnect from the server.
    ///
    /// Returns a result of the error variant if an error occurred while disconnecting.
    ///
    /// ```no_run
    /// use rustdtp::*;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     // Create the client
    ///     let (mut client, mut client_events) = Client::builder()
    ///         .sending::<()>()
    ///         .receiving::<String>()
    ///         .with_event_channel()
    ///         .connect(("127.0.0.1", 29275))
    ///         .await
    ///         .unwrap();
    ///
    ///     // Wait for events until the server requests the client leave
    ///     while let Some(event) = client_events.next().await {
    ///         match event {
    ///             ClientEvent::Receive { data } => {
    ///                 if data.as_str() == "Kindly leave" {
    ///                     println!("Client disconnect requested");
    ///                     client.disconnect().await.unwrap();
    ///                     break;
    ///                 }
    ///             }
    ///             _ => {}  // Do nothing for other events
    ///         }
    ///     }
    /// }
    /// ```
    pub async fn disconnect(mut self) -> io::Result<()> {
        let value = self
            .client_command_sender
            .send_command(ClientCommand::Disconnect)
            .await?;
        self.client_task_handle.await.unwrap()?;
        unwrap_enum!(value, ClientCommandReturn::Disconnect)
    }

    /// Send data to the server.
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
    ///     // Create the client
    ///     let (mut client, mut client_events) = Client::builder()
    ///         .sending::<String>()
    ///         .receiving::<()>()
    ///         .with_event_channel()
    ///         .connect(("127.0.0.1", 29275))
    ///         .await
    ///         .unwrap();
    ///
    ///     // Send a greeting to the server upon connecting
    ///     client.send("Hello, server!".to_owned()).await.unwrap();
    /// }
    /// ```
    pub async fn send(&mut self, data: S) -> io::Result<()> {
        let value = self
            .client_command_sender
            .send_command(ClientCommand::Send { data })
            .await?;
        unwrap_enum!(value, ClientCommandReturn::Send)
    }

    /// Get the address of the socket the client is connected on.
    ///
    /// Returns a result containing the address of the socket the client is connected on, or the error variant if an error occurred.
    ///
    /// ```no_run
    /// use rustdtp::*;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     // Create the client
    ///     let (mut client, mut client_events) = Client::builder()
    ///         .sending::<String>()
    ///         .receiving::<()>()
    ///         .with_event_channel()
    ///         .connect(("127.0.0.1", 29275))
    ///         .await
    ///         .unwrap();
    ///
    ///     // Get the client address
    ///     let addr = client.get_addr().await.unwrap();
    ///     println!("Client connected on {}", addr);
    /// }
    /// ```
    pub async fn get_addr(&mut self) -> io::Result<SocketAddr> {
        let value = self
            .client_command_sender
            .send_command(ClientCommand::GetAddr)
            .await?;
        unwrap_enum!(value, ClientCommandReturn::GetAddr)
    }

    /// Get the address of the server.
    ///
    /// Returns a result containing the address of the server, or the error variant if an error occurred.
    ///
    /// ```no_run
    /// use rustdtp::*;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     // Create the client
    ///     let (mut client, mut client_events) = Client::builder()
    ///         .sending::<String>()
    ///         .receiving::<()>()
    ///         .with_event_channel()
    ///         .connect(("127.0.0.1", 29275))
    ///         .await
    ///         .unwrap();
    ///
    ///     // Get the server address
    ///     let addr = client.get_server_addr().await.unwrap();
    ///     println!("Server address: {}", addr);
    /// }
    /// ```
    pub async fn get_server_addr(&mut self) -> io::Result<SocketAddr> {
        let value = self
            .client_command_sender
            .send_command(ClientCommand::GetServerAddr)
            .await?;
        unwrap_enum!(value, ClientCommandReturn::GetServerAddr)
    }
}

/// A socket client.
///
/// The client takes two generic parameters:
///
/// - `S`: the type of data that will be **sent** to the server.
/// - `R`: the type of data that will be **received** from the server.
///
/// Both types must be serializable in order to be sent through the socket. When creating a server, the types should be swapped, since the client's send type will be the server's receive type and vice versa.
///
/// ```no_run
/// use rustdtp::*;
///
/// #[tokio::main]
/// async fn main() {
///     // Create a client that sends a message to the server and receives the length of the message
///     let (mut client, mut client_events) = Client::builder()
///         .sending::<String>()
///         .receiving::<usize>()
///         .with_event_channel()
///         .connect(("127.0.0.1", 29275))
///         .await
///         .unwrap();
///
///     // Send a message to the server
///     let msg = "Hello, server!".to_owned();
///     client.send(msg.clone()).await.unwrap();
///
///     // Receive the response
///     match client_events.next().await.unwrap() {
///         ClientEvent::Receive { data } => {
///             // Validate the response
///             println!("Received response from server: {}", data);
///             assert_eq!(data, msg.len());
///         }
///         event => {
///             // Unexpected response
///             panic!("expected to receive a response from the server, instead got {:?}", event);
///         }
///     }
/// }
/// ```
pub struct Client<S, R>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    /// Phantom value for `S`.
    phantom_send: PhantomData<S>,
    /// Phantom value for `R`.
    phantom_receive: PhantomData<R>,
}

impl Client<(), ()> {
    /// Constructs a client builder. Use this for a clearer, more explicit,
    /// and more featureful client configuration. See [`ClientBuilder`] for
    /// more information.
    pub fn builder(
    ) -> ClientBuilder<ClientSendingUnknown, ClientReceivingUnknown, ClientEventReportingUnknown>
    {
        ClientBuilder::new()
    }
}

impl<S, R> Client<S, R>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    /// Connect to a socket server.
    ///
    /// `addr`: the address to connect to.
    ///
    /// Returns a result containing a handle to the client and a channel from which to receive client events, or the error variant if an error occurred while connecting to the server.
    ///
    /// ```no_run
    /// use rustdtp::*;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let (mut client, mut client_events) = Client::builder()
    ///         .sending::<()>()
    ///         .receiving::<()>()
    ///         .with_event_channel()
    ///         .connect(("127.0.0.1", 29275))
    ///         .await
    ///         .unwrap();
    /// }
    /// ```
    ///
    /// Neither the client handle nor the event receiver should be dropped until the client has disconnected. Prematurely dropping either one can cause unintended behavior.
    pub async fn connect<A>(addr: A) -> io::Result<(ClientHandle<S>, EventStream<ClientEvent<R>>)>
    where
        A: ToSocketAddrs,
    {
        // Client TCP stream
        let mut stream = TcpStream::connect(addr).await?;

        // Buffer in which to receive the size portion of the RSA public key
        let mut rsa_pub_size_buffer = [0; LEN_SIZE];
        // Read size portion of RSA public key
        let n_size = handshake_timeout! {
            stream.read(&mut rsa_pub_size_buffer)
        }??;

        // If there were no bytes read, or if there were fewer bytes read than there
        // should have been, close the stream and exit
        if n_size != LEN_SIZE {
            stream.shutdown().await?;
            return generic_io_error("failed to read RSA public key size from stream");
        };

        // Decode the size portion of the RSA public key
        let rsa_pub_size = decode_message_size(&rsa_pub_size_buffer);
        // Initialize the buffer for the RSA public key
        let mut rsa_pub_buffer = vec![0; rsa_pub_size];

        // Read the RSA public key portion from the stream, returning an error if the
        // stream could not be read
        let n_rsa_pub = data_read_timeout! {
            stream.read(&mut rsa_pub_buffer)
        }??;

        // If there were no bytes read, or if there were fewer bytes read than there
        // should have been, close the stream and exit
        if n_rsa_pub != rsa_pub_size {
            stream.shutdown().await?;
            return generic_io_error("failed to read RSA public key data from stream");
        }

        // Read the RSA public key into a string, returning an error if UTF-8 conversion failed
        let rsa_pub_str = into_generic_io_result(String::from_utf8(rsa_pub_buffer))?;
        // Read the RSA public key string into an RSA public key object
        let rsa_pub = into_generic_io_result(RsaPublicKey::from_public_key_pem(&rsa_pub_str))?;

        // Generate AES key
        let aes_key = aes_key().await;
        // Encrypt AES key with RSA public key
        let aes_key_encrypted = into_generic_io_result(rsa_encrypt(rsa_pub, aes_key.into()).await)?;
        // Create the buffer containing the AES key and its size
        let mut aes_key_buffer = encode_message_size(aes_key_encrypted.len()).to_vec();
        // Extend the buffer with the AES key
        aes_key_buffer.extend(aes_key_encrypted);
        // Send the encrypted AES key to the server
        let n = stream.write(&aes_key_buffer).await?;
        // Flush the stream
        stream.flush().await?;

        // If there were no bytes written, or if there were fewer
        // bytes written than there should have been, close the
        // stream and exit
        if n != aes_key_buffer.len() {
            stream.shutdown().await?;
            return generic_io_error("failed to write encrypted AES key data to stream");
        }

        // Channels for sending commands from the client handle to the background client task
        let (client_command_sender, client_command_receiver) = command_channel();
        // Channels for sending event notifications from the background client task
        let (client_event_sender, client_event_receiver) = channel(CHANNEL_BUFFER_SIZE);

        // Start the background client task, saving the join handle for when the client disconnects
        let client_task_handle = tokio::spawn(client_loop(
            stream,
            aes_key,
            client_event_sender,
            client_command_receiver,
        ));

        // Create a handle for the client
        let client_handle = ClientHandle {
            client_command_sender,
            client_task_handle,
        };

        // Create an event stream for the client
        let client_event_stream = EventStream::new(client_event_receiver);

        Ok((client_handle, client_event_stream))
    }
}

/// The client loop. Handles received data and commands.
async fn client_loop<S, R>(
    mut stream: TcpStream,
    aes_key: [u8; AES_KEY_SIZE],
    client_event_sender: Sender<ClientEvent<R>>,
    mut client_command_receiver: CommandChannelReceiver<ClientCommand<S>, ClientCommandReturn>,
) -> io::Result<()>
where
    S: Serialize + Send + 'static,
    R: DeserializeOwned + Send + 'static,
{
    // Buffer in which to receive the size portion of a message
    let mut size_buffer = [0; LEN_SIZE];

    // Client loop
    loop {
        // Await messages from the server
        // and commands from the client handle
        tokio::select! {
            // Read the size portion from the stream
            read_value = stream.read(&mut size_buffer) => {
                // Return an error if the stream could not be read
                let n_size = read_value?;

                // If there were no bytes read, or if there were fewer bytes read than there
                // should have been, close the stream
                if n_size != LEN_SIZE {
                    stream.shutdown().await?;
                    break;
                }

                // Decode the size portion of the message
                let encrypted_data_size = decode_message_size(&size_buffer);
                // Initialize the buffer for the data portion of the message
                let mut encrypted_data_buffer = vec![0; encrypted_data_size];

                // Read the data portion from the client stream, returning an error if the
                // stream could not be read
                let n_data = data_read_timeout! {
                    stream.read(&mut encrypted_data_buffer)
                }??;

                // If there were no bytes read, or if there were fewer bytes read than there
                // should have been, close the stream
                if n_data != encrypted_data_size {
                    stream.shutdown().await?;
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
                    // the server
                    if let Err(_e) = client_event_sender.send(ClientEvent::Receive { data }).await {
                        // Sending failed, disconnect
                        stream.shutdown().await?;
                        break;
                    }
                } else {
                    // Deserialization failed, disconnect
                    stream.shutdown().await?;
                    break;
                }
            }
            // Process a command from the client handle
            command_value = client_command_receiver.recv_command() => {
                // Handle the command, or lack thereof if the channel is closed
                match command_value {
                    Ok(command) => {
                        match command {
                            ClientCommand::Disconnect => {
                                // Disconnect from the server
                                let value = stream.shutdown().await;

                                // If a command fails to send, the client has already disconnected,
                                // and the error can be ignored.
                                // It should be noted that this is not where the disconnect method actually returns
                                // its `Result`. This immediately returns with an `Ok` status. The real return
                                // value is the `Result` returned from the client task join handle.
                                _ = client_command_receiver.command_return(ClientCommandReturn::Disconnect(value)).await;

                                // Break the client loop
                                break;
                            },
                            ClientCommand::Send { data } => {
                                let value = 'val: {
                                    // Serialize the data
                                    let data_buffer = break_on_err!(into_generic_io_result(serde_json::to_vec(&data)), 'val);
                                    // Encrypt the serialized data
                                    let encrypted_data_buffer = break_on_err!(into_generic_io_result(aes_encrypt(aes_key, data_buffer.into()).await), 'val);
                                    // Encode the message size to a buffer
                                    let size_buffer = encode_message_size(encrypted_data_buffer.len());

                                    // Initialize the message buffer
                                    let mut buffer = vec![];
                                    // Extend the buffer to contain the payload size
                                    buffer.extend_from_slice(&size_buffer);
                                    // Extend the buffer to contain the payload data
                                    buffer.extend(&encrypted_data_buffer);

                                    // Write the data to the stream
                                    let n = break_on_err!(stream.write(&buffer).await, 'val);
                                    // Flush the stream
                                    break_on_err!(stream.flush().await, 'val);

                                    // If there were no bytes written, or if there were fewer
                                    // bytes written than there should have been, close the
                                    // stream
                                    if n != buffer.len() {
                                        generic_io_error("failed to write data to stream")
                                    } else {
                                        Ok(())
                                    }
                                };

                                let error_occurred = value.is_err();

                                // Return the status of the send operation
                                if let Err(_e) = client_command_receiver.command_return(ClientCommandReturn::Send(value)).await {
                                    // Channel is closed, disconnect from the server
                                    stream.shutdown().await?;
                                    break;
                                }

                                // If the send failed, disconnect from the server
                                if error_occurred {
                                    stream.shutdown().await?;
                                    break;
                                }
                            },
                            ClientCommand::GetAddr => {
                                // Get the stream's address
                                let addr = stream.local_addr();

                                // Return the address
                                if let Err(_e) = client_command_receiver.command_return(ClientCommandReturn::GetAddr(addr)).await {
                                    // Channel is closed, disconnect from the server
                                    stream.shutdown().await?;
                                    break;
                                }
                            },
                            ClientCommand::GetServerAddr => {
                                // Get the stream's address
                                let addr = stream.peer_addr();

                                // Return the address
                                if let Err(_e) = client_command_receiver.command_return(ClientCommandReturn::GetServerAddr(addr)).await {
                                    // Channel is closed, disconnect from the server
                                    stream.shutdown().await?;
                                    break;
                                }
                            },
                        }
                    },
                    Err(_e) => {
                        // Client probably disconnected, exit
                        stream.shutdown().await?;
                        break;
                    }
                }
            }
        }
    }

    // Send a disconnect event, ignoring send errors
    if let Err(_e) = client_event_sender.send(ClientEvent::Disconnect).await {}

    Ok(())
}
