use super::*;
pub(crate) async fn socket_write_fixed_string(
    socket: &mut TcpStream,
    s: &String,
    len: usize,
) -> Result<()> {
    let mut path = s.clone().into_bytes();
    assert!(path.len() <= len);
    path.resize(len, 0);
    socket.write_all(&path).await
}
