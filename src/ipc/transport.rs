use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Read a length-prefixed message from a generic stream
pub async fn read_frame<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Read 4-byte big-endian length prefix
    let mut length_buf = [0u8; 4];
    stream
        .read_exact(&mut length_buf)
        .await
        .context("Failed to read message length")?;

    let message_length = u32::from_be_bytes(length_buf) as usize;

    // Sanity check: prevent excessive memory allocation
    if message_length > 1024 * 1024 {
        // 1MB limit
        return Err(anyhow!("Message too large: {} bytes", message_length));
    }

    // Read message body
    let mut message_buf = vec![0u8; message_length];
    stream
        .read_exact(&mut message_buf)
        .await
        .context("Failed to read message body")?;

    Ok(message_buf)
}

/// Write a length-prefixed message to a generic stream
pub async fn write_frame<S>(stream: &mut S, message: &[u8]) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Write 4-byte big-endian length prefix
    let length = message.len() as u32;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .context("Failed to write message length")?;

    // Write message body
    stream
        .write_all(message)
        .await
        .context("Failed to write message body")?;

    stream.flush().await.context("Failed to flush stream")?;

    Ok(())
}
