use async_std::channel::{bounded, Receiver, SendError, Sender};
use std::io;

/// An error associated with a command channel.
pub enum CommandChannelError<T> {
    /// An error occurred when sending a command.
    SendCommandError(SendError<T>),
    /// An error occurred when sending the return value of a command.
    SendCommandReturnError(SendError<T>),
    /// The command channel is closed.
    ChannelClosed,
}

impl<T> CommandChannelError<T> {
    /// Gets the message associated with a command channel error.
    pub fn message(&self) -> &'static str {
        "command channel closed"
    }
}

impl<T> From<CommandChannelError<T>> for io::Error {
    fn from(e: CommandChannelError<T>) -> Self {
        Self::new(io::ErrorKind::Other, e.message())
    }
}

/// A command channel sender.
///
/// The command channel sender takes two generic parameters:
///
/// - `S`: the type representing the command.
/// - `R`: the type representing the return value from the command.
pub struct CommandChannelSender<S, R> {
    /// The channel through which commands are sent.
    command_sender: Sender<S>,
    /// The channel through which command return values are received.
    command_return_receiver: Receiver<R>,
}

impl<S, R> CommandChannelSender<S, R> {
    /// Send a command to the receiver.
    ///
    /// `command`: the command to send.
    ///
    /// Returns a result containing the received return value of the command, or the error variant if an error occurred while interacting with the channel.
    pub async fn send_command(&self, command: S) -> Result<R, CommandChannelError<S>> {
        match self.command_sender.send(command).await {
            Ok(()) => Ok(()),
            Err(e) => Err(CommandChannelError::SendCommandError(e)),
        }?;

        match self.command_return_receiver.recv().await {
            Ok(value) => Ok(value),
            Err(_e) => Err(CommandChannelError::ChannelClosed),
        }
    }
}

/// A command channel receiver.
///
/// The command channel receiver takes two generic parameters:
///
/// - `S`: the type representing the command.
/// - `R`: the type representing the return value from the command.
pub struct CommandChannelReceiver<S, R> {
    /// The channel through which commands are received.
    command_receiver: Receiver<S>,
    /// The channel through which commands return values are sent.
    command_return_sender: Sender<R>,
}

impl<S, R> CommandChannelReceiver<S, R> {
    /// Receive a command from the command channel.
    ///
    /// Returns a result containing the received command, or the error variant if an error occurred while interacting with the channel.
    pub async fn recv_command(&self) -> Result<S, CommandChannelError<S>> {
        let command = match self.command_receiver.recv().await {
            Ok(value) => Ok(value),
            Err(_e) => Err(CommandChannelError::ChannelClosed),
        }?;

        Ok(command)
    }

    /// Pass the return value of a command through the channel back to the sender.
    ///
    /// `command_return`: the return value of the command.
    ///
    /// Returns a result of the error variant if an error occurred while interacting with the channel.
    pub async fn command_return(&self, command_return: R) -> Result<(), CommandChannelError<R>> {
        match self.command_return_sender.send(command_return).await {
            Ok(()) => Ok(()),
            Err(e) => Err(CommandChannelError::SendCommandReturnError(e)),
        }
    }
}

/// Create a sender-receiver pair of command channels.
///
/// This takes two generic parameters:
///
/// - `S`: the type representing the command.
/// - `R`: the type representing the return value from the command.
///
/// The internal channels are buffered to support only a single value. This is because only one command should be processed at a time.
pub fn command_channel<S, R>() -> (CommandChannelSender<S, R>, CommandChannelReceiver<S, R>) {
    let (command_sender, command_receiver) = bounded(1);
    let (command_return_sender, command_return_receiver) = bounded(1);

    let sender = CommandChannelSender {
        command_sender,
        command_return_receiver,
    };
    let receiver = CommandChannelReceiver {
        command_receiver,
        command_return_sender,
    };

    (sender, receiver)
}
