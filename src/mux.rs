//! Minimal multiplexing layer built on `tokio-yamux`.
//!
//! Motivation: rathole normally opens one new TCP (or noise) connection per
//! visitor data channel. On lossy / intermediated paths (e.g. a hospital
//! network gate doing L4 SNAT) that "new connection per request" churn is the
//! main source of instability. This module lets all data channels of a service
//! ride over a single persistent carrier connection as yamux logical streams.
//!
//! It is intentionally additive and off by default (`[client] mux` /
//! `[server] mux`). When a mux-capable client meets a legacy server it
//! auto-falls back to the per-connection mode (see `client.rs`).

use std::io;
use std::sync::Arc;

use futures::StreamExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio_yamux::config::Config;
use tokio_yamux::session::Session;

/// Combined read+write supertrait so it can be the single principal trait of a
/// trait object (Rust allows only one non-auto trait in `dyn A + B`).
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// A data-channel stream whose concrete transport type has been erased, so the
/// connection pool can hold both legacy per-connection streams (`T::Stream`)
/// and multiplexed yamux `StreamHandle`s in the same channel.
pub type BoxedStream = Box<dyn AsyncReadWrite + Unpin + Send>;

fn other_err(msg: impl Into<std::borrow::Cow<'static, str>>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.into())
}

/// Client-side handle to a yamux session running on one persistent carrier
/// connection. The `Session` is owned by a driver task (yamux needs to be
/// polled continuously to pump frames); `open_stream` requests are funneled to
/// that task over a channel so streams can still be created on demand.
pub struct MuxClientHandle {
    open_tx: mpsc::Sender<oneshot::Sender<Result<BoxedStream, io::Error>>>,
}

impl MuxClientHandle {
    /// Take ownership of an already-handshaked carrier connection (the
    /// `MuxChannelHello`/`Ack` preamble must have been exchanged by the caller
    /// *before* this point) and start driving a yamux client session on it.
    pub fn start<T>(conn: T) -> Arc<MuxClientHandle>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let mut session = Session::new_client(conn, Config::default());
        let (open_tx, mut open_rx) =
            mpsc::channel::<oneshot::Sender<Result<BoxedStream, io::Error>>>(64);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Serve an on-demand "open a data channel" request.
                    reply = open_rx.recv() => {
                        match reply {
                            Some(reply) => {
                                let res = session
                                    .open_stream()
                                    .map(|h| Box::new(h) as BoxedStream)
                                    .map_err(|e| other_err(format!("{:?}", e)));
                                let _ = reply.send(res);
                            }
                            // All senders dropped -> caller is gone, stop.
                            None => break,
                        }
                    }
                    // Keep driving the session so all open streams make
                    // progress. Inbound streams are not expected on the
                    // client carrier, so discard them.
                    driven = session.next() => {
                        if driven.is_none() {
                            // Connection closed by the peer.
                            break;
                        }
                    }
                }
            }
            debug_assert!(true);
        });

        Arc::new(MuxClientHandle { open_tx })
    }

    /// Open one logical stream (a data channel) over the carrier connection.
    pub async fn open_stream(&self) -> Result<BoxedStream, io::Error> {
        let (tx, rx) = oneshot::channel();
        self.open_tx
            .send(tx)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mux driver gone"))?;
        rx.await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "mux reply lost"))?
    }
}

/// Server side of the carrier: wrap the connection in a yamux server session
/// and push every accepted inbound stream (as a `BoxedStream`) into
/// `accept_tx`, which feeds the existing data-channel pool.
pub async fn serve_mux<T>(conn: T, accept_tx: mpsc::Sender<BoxedStream>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut session = Session::new_server(conn, Config::default());
    while let Some(maybe_stream) = session.next().await {
        match maybe_stream {
            Ok(stream) => {
                if accept_tx.send(Box::new(stream) as BoxedStream).await.is_err() {
                    break; // pool gone
                }
            }
            Err(_) => break, // session error -> carrier dead
        }
    }
}
