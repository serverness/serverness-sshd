use anyhow::{Context, bail};
use clap::Parser;
use dashmap::DashMap;
use pty_process::{OwnedWritePty, Pts};
use russh::{
    Channel,
    keys::PrivateKey,
    server::{Handler, Msg, Server, Session},
};
use russh::{ChannelId, CryptoVec, server::*};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::ChildStdin;
use tracing::{error, info, instrument, trace};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(long, required = true)]
    hostkey: Vec<PathBuf>,

    #[arg(long)]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .pretty()
                // Use span events to automatically log each of the SSH handlers.
                .with_span_events(tracing_subscriber::fmt::format::FmtSpan::NEW),
        )
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Cli::parse();

    let keys: Vec<PrivateKey> = args
        .hostkey
        .iter()
        .map(|path| {
            russh::keys::load_secret_key(path, None).unwrap_or_else(|e| {
                error!(?path, ?e, "Failed to load the host key");

                std::process::exit(1);
            })
        })
        .collect();

    let config = russh::server::Config {
        auth_rejection_time: Duration::from_secs(3),
        keys,
        ..Default::default()
    };

    let mut sshd = SshServer {};

    let address = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 2222);

    sshd.run_on_address(Arc::new(config), address)
        .await
        .context("Failed to start the ssh server")?;

    Ok(())
}

struct SshServer {}

impl SshServer {}

enum NessChannelState {
    Plain,
    Interactive {
        col_width: u32,
        row_height: u32,
        pts: Pts,
        writer: OwnedWritePty,
    },
    Exec {
        abort_handle: AbortOnDrop,
        writer: ChildStdin,
    },
    PtyExec {
        abort_handle: AbortOnDrop,
        writer: OwnedWritePty,
    },
}

struct NessChannel {
    state: NessChannelState,
}

struct ServerHandler {
    span: tracing::Span,

    client_id: Uuid,
    client_address: Option<SocketAddr>,

    channels: Arc<DashMap<ChannelId, NessChannel>>,
}

impl Server for SshServer {
    type Handler = ServerHandler;

    fn new_client(&mut self, client_address: Option<std::net::SocketAddr>) -> Self::Handler {
        let client_id = Uuid::now_v7();
        let span = tracing::span!(tracing::Level::INFO, "connection", ?client_id);
        let channels = Arc::new(DashMap::new());

        Self::Handler {
            span,
            client_id,
            client_address,
            channels,
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as Handler>::Error) {
        error!(?error, "session error");
    }
}

struct AbortOnDrop {
    inner: tokio::task::AbortHandle,
}

impl AbortOnDrop {
    fn new<T>(inner: tokio::task::JoinHandle<T>) -> Self {
        Self {
            inner: inner.abort_handle(),
        }
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.inner.abort();
    }
}

impl ServerHandler {
    async fn wait_and_close_channel(
        &self,
        channel_id: ChannelId,
        handle: russh::server::Handle,
        mut child: tokio::process::Child,
    ) -> AbortOnDrop {
        let client_address = self.client_address;
        let client_id = self.client_id;
        AbortOnDrop::new(tokio::spawn(async move {
            let exit_status = child.wait().await.unwrap();
            close_channel(client_address, client_id, &handle, channel_id, &exit_status).await;
            drop(child);
        }))
    }
}

impl Handler for ServerHandler {
    type Error = anyhow::Error;

    #[instrument(parent = &self.span, skip(self))]
    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    #[instrument(parent = &self.span, skip(self, session))]
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        println!("channel open session");

        self.channels.insert(
            channel.id(),
            NessChannel {
                state: NessChannelState::Plain,
            },
        );

        Ok(true)
    }

    #[instrument(parent = &self.span, skip(self, session))]
    async fn pty_request(
        &mut self,
        channel_id: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut channel = self
            .channels
            .get_mut(&channel_id)
            .context("No channel found")?;

        match channel.state {
            NessChannelState::Plain => {
                let (pty, pts) = pty_process::open().context("Failed to open a PTY")?;

                let (reader, writer) = pty.into_split();

                pipe_to_channel(channel_id, session.handle(), reader).await;

                channel.state = NessChannelState::Interactive {
                    col_width,
                    row_height,
                    pts,
                    writer,
                };
            }
            _ => {}
        }

        Ok(())
    }

    #[instrument(parent = &self.span, skip(self, session))]
    async fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let handle = session.handle();

        let (_, mut channel) = self
            .channels
            .remove(&channel_id)
            .context("No channel found")?;

        let next_state = match channel.state {
            NessChannelState::Plain => {
                let mut child = tokio::process::Command::new("bash")
                    .env_clear()
                    .kill_on_drop(true)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .context("Failed to spawn a process")?;

                info!(pid = child.id(), "process spawned");

                let stdout = child.stdout.take().context("Failed to take the stdout")?;
                pipe_to_channel(channel_id, handle.clone(), stdout).await;

                let stderr = child.stderr.take().context("Failed to take the stderr")?;
                pipe_to_channel(channel_id, handle.clone(), stderr).await;

                let writer = child.stdin.take().context("Failed to take the stdin")?;

                let abort_handle = self.wait_and_close_channel(channel_id, handle, child).await;

                Some(NessChannelState::Exec {
                    abort_handle,
                    writer,
                })
            }

            NessChannelState::Interactive {
                col_width,
                row_height,
                pts,
                writer,
            } => {
                let child = pty_process::Command::new("bash")
                    .env_clear()
                    .kill_on_drop(true)
                    .spawn(pts)
                    .context("Failed to spawn a process")?;

                info!(pid = child.id(), "process spawned");

                let abort_handle = self.wait_and_close_channel(channel_id, handle, child).await;

                writer
                    .resize(pty_process::Size::new(row_height as u16, col_width as u16))
                    .context("Failed to resize the PTY")?;

                Some(NessChannelState::PtyExec {
                    abort_handle,
                    writer,
                })
            }

            _ => bail!("Expected Plain or Interactive sessions"),
        };

        if let Some(state) = next_state {
            channel.state = state;

            self.channels.insert(channel_id, channel);
        }

        Ok(())
    }

    #[instrument(parent = &self.span, skip(self, session))]
    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let cmd = String::from_utf8(data.to_vec())?;
        info!(?cmd);

        let handle = session.handle();

        let (_, mut channel) = self
            .channels
            .remove(&channel_id)
            .context("No channel found")?;

        let next_state = match channel.state {
            NessChannelState::Plain => {
                let mut child = tokio::process::Command::new(cmd)
                    .env_clear()
                    .kill_on_drop(true)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .context("Failed to spawn a command")?;

                info!(pid = child.id(), "process spawned");

                let stdout = child.stdout.take().context("Failed to take the stdout")?;
                pipe_to_channel(channel_id, handle.clone(), stdout).await;

                let stderr = child.stderr.take().context("Failed to take the stderr")?;
                pipe_to_channel(channel_id, handle.clone(), stderr).await;

                let writer = child.stdin.take().context("Failed to take the stdin")?;

                let abort_handle = self.wait_and_close_channel(channel_id, handle, child).await;

                Some(NessChannelState::Exec {
                    abort_handle,
                    writer,
                })
            }

            NessChannelState::Interactive {
                col_width,
                row_height,
                pts,
                writer,
            } => {
                let child = pty_process::Command::new(cmd)
                    .env_clear()
                    .kill_on_drop(true)
                    .spawn(pts)
                    .context("Failed to spawn a process")?;

                info!(pid = child.id(), "process spawned");

                let abort_handle = self.wait_and_close_channel(channel_id, handle, child).await;

                writer
                    .resize(pty_process::Size::new(row_height as u16, col_width as u16))
                    .context("Failed to resite the PTY")?;

                Some(NessChannelState::PtyExec {
                    abort_handle,
                    writer,
                })
            }

            _ => None,
        };

        if let Some(state) = next_state {
            channel.state = state;

            self.channels.insert(channel_id, channel);
        }

        Ok(())
    }

    #[instrument(parent = &self.span, skip(self, session))]
    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let mut channel = self
            .channels
            .get_mut(&channel)
            .context("no channel found")?;

        match channel.state {
            NessChannelState::PtyExec { ref mut writer, .. } => {
                writer.resize(pty_process::Size::new(row_height as u16, col_width as u16))?;
            }
            _ => bail!("expected interactive session"),
        }

        Ok(())
    }

    #[instrument(parent = &self.span, level = "trace", skip(self, _session))]
    async fn data(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        trace!(data = ?String::from_utf8_lossy(data));

        let mut channel = self.channels.get_mut(&channel_id).unwrap();

        match channel.state {
            NessChannelState::Exec { ref mut writer, .. } => {
                trace!(?data, "writing to exec");
                writer
                    .write_all(data)
                    .await
                    .context("Failed to write to stdin")?;
            }

            NessChannelState::PtyExec { ref mut writer, .. } => {
                trace!(?data, "writing to pty exec");
                writer
                    .write_all(data)
                    .await
                    .context("Failed to write to PTY")?;
            }

            _ => bail!("Expected execution"),
        }

        Ok(())
    }

    #[tracing::instrument(parent = &self.span, skip(self, _session))]
    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        drop(self.channels.remove(&channel));
        Ok(())
    }

    #[tracing::instrument(parent = &self.span, skip(self, session))]
    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let handle = session.handle();
        close_channel(
            self.client_address,
            self.client_id,
            &handle,
            channel,
            &std::process::ExitStatus::from_raw(0),
        )
        .await;
        drop(self.channels.remove(&channel));
        Ok(())
    }
}

async fn pipe_to_channel<R>(
    channel_id: ChannelId,
    handle: russh::server::Handle,
    mut reader: R,
) -> tokio::task::JoinHandle<()>
where
    R: tokio::io::AsyncReadExt + std::marker::Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buffer = vec![0; 1024];
        while let Ok(n) = reader.read(&mut buffer).await {
            if n == 0 {
                break;
            }

            if let Err(error) = handle
                .data(channel_id, CryptoVec::from_slice(&buffer[0..n]))
                .await
            {
                error!(channel_id = ?channel_id, ?error, "failed on writing to channel");
                break;
            }
        }
    })
}

async fn close_channel(
    client_address: Option<SocketAddr>,
    client_id: Uuid,
    handle: &russh::server::Handle,
    channel_id: ChannelId,
    exit_status: &std::process::ExitStatus,
) {
    // NOTE: .code() can return None when the child process is killed via a
    // signal like ctrl-c.
    let our_exit_status: u32 = match (exit_status.code(), exit_status.signal()) {
        (Some(code), None) => code.try_into().unwrap_or(1),
        (None, Some(signal)) => signal as u32 + 128,
        _ => unreachable!(),
    };

    // Note: these can fail. I have no idea why.
    if let Err(error) = handle
        .exit_status_request(channel_id, our_exit_status)
        .await
    {
        // todo: track error
    }
    if let Err(error) = handle.eof(channel_id).await {
        // todo: track error
    }
    if let Err(error) = handle.close(channel_id).await {
        // todo: track error
    }
}
