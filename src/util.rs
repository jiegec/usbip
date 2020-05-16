use super::*;
pub(crate) async fn socket_write_fixed_string<T: AsyncReadExt + AsyncWriteExt + Unpin>(
    socket: &mut T,
    s: &String,
    len: usize,
) -> Result<()> {
    let mut path = s.clone().into_bytes();
    assert!(path.len() <= len);
    path.resize(len, 0);
    socket.write_all(&path).await
}

pub fn verify_descriptor(desc: &[u8]) {
    let mut offset = 0;
    while offset < desc.len() {
        offset += desc[offset] as usize; // length
    }
    assert_eq!(offset, desc.len());
}