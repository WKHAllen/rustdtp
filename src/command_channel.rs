use tokio::sync::mpsc::{channel, error::SendError, Receiver, Sender};

pub enum CommandChannelError<T> {
    SendCommandError(SendError<T>),
    SendCommandReturnError(SendError<T>),
    ChannelClosed,
}

pub struct CommandChannelSender<S, R> {
    command_sender: Sender<S>,
    command_return_receiver: Receiver<R>,
}

impl<S, R> CommandChannelSender<S, R> {
    pub async fn send(&mut self, command: S) -> Result<R, CommandChannelError<S>> {
        match self.command_sender.send(command).await {
            Ok(()) => Ok(()),
            Err(e) => Err(CommandChannelError::SendCommandError(e)),
        }?;

        match self.command_return_receiver.recv().await {
            Some(value) => Ok(value),
            None => Err(CommandChannelError::ChannelClosed),
        }
    }
}

pub struct CommandChannelReceiver<S, R> {
    command_receiver: Receiver<S>,
    command_return_sender: Sender<R>,
}

impl<S, R> CommandChannelReceiver<S, R> {
    pub async fn recv(&mut self) -> Result<S, CommandChannelError<S>> {
        let command = match self.command_receiver.recv().await {
            Some(value) => Ok(value),
            None => Err(CommandChannelError::ChannelClosed),
        }?;

        Ok(command)
    }

    pub async fn send(&mut self, command_return: R) -> Result<(), CommandChannelError<R>> {
        match self.command_return_sender.send(command_return).await {
            Ok(()) => Ok(()),
            Err(e) => Err(CommandChannelError::SendCommandReturnError(e)),
        }
    }
}

pub fn command_channel<S, R>() -> (CommandChannelSender<S, R>, CommandChannelReceiver<S, R>) {
    let (command_sender, command_receiver) = channel(1);
    let (command_return_sender, command_return_receiver) = channel(1);

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
