use super::*;

pub(crate) async fn socket_write_fixed_string<T: AsyncReadExt + AsyncWriteExt + Unpin>(
    socket: &mut T,
    s: &str,
    len: usize,
) -> Result<()> {
    let mut path = s.as_bytes().to_vec();
    assert!(path.len() <= len);
    path.resize(len, 0);
    socket.write_all(&path).await
}

/// Check validity of a USB descriptor
pub fn verify_descriptor(desc: &[u8]) {
    let mut offset = 0;
    while offset < desc.len() {
        offset += desc[offset] as usize; // length
    }
    assert_eq!(offset, desc.len());
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        io::*,
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::{
        io::{AsyncRead, AsyncWrite, ReadBuf},
        net::{TcpListener, TcpStream},
    };

    pub(crate) struct MockSocket {
        pub input: Cursor<Vec<u8>>,
        pub output: Vec<u8>,
    }

    impl MockSocket {
        pub(crate) fn new(input: Vec<u8>) -> Self {
            Self {
                input: Cursor::new(input),
                output: vec![],
            }
        }
    }

    impl AsyncRead for MockSocket {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context,
            buf: &mut ReadBuf,
        ) -> Poll<Result<()>> {
            // safe, see https://doc.rust-lang.org/std/pin/index.html#pinning-is-structural-for-field
            unsafe { self.map_unchecked_mut(|s| &mut s.input).poll_read(cx, buf) }
        }
    }

    #[cfg(test)]
    impl AsyncWrite for MockSocket {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize>> {
            self.get_mut().output.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    pub(crate) async fn get_free_address() -> SocketAddr {
        let stream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        stream.local_addr().unwrap()
    }

    pub(crate) async fn poll_connect(addr: SocketAddr) -> TcpStream {
        loop {
            if let Ok(stream) = TcpStream::connect(addr).await {
                return stream;
            }
        }
    }

    pub(crate) fn setup_test_logger() {
        let _ = env_logger::builder().is_test(true).try_init();
    }
}
