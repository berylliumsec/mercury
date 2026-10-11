use anyhow::{Context, anyhow};
use control_api::{ControlRequest, ControlResponse, decode_response, encode_request};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::time::{Instant, sleep, timeout};

const CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_RETRY_WINDOW: Duration = Duration::from_secs(5);
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(200);

pub async fn send_request(
    socket: &str,
    request: &ControlRequest,
) -> anyhow::Result<ControlResponse> {
    #[cfg(unix)]
    {
        send_request_unix(socket, request).await
    }
}

#[cfg(unix)]
async fn send_request_unix(
    socket: &str,
    request: &ControlRequest,
) -> anyhow::Result<ControlResponse> {
    let mut stream = connect_with_retry(socket).await?;

    let frame = encode_request(request).context("encode control request")?;
    timeout(CONTROL_IO_TIMEOUT, stream.write_all(&frame))
        .await
        .context("timed out sending control request")?
        .context("send control request")?;
    timeout(CONTROL_IO_TIMEOUT, stream.flush())
        .await
        .context("timed out flushing control request")?
        .context("flush control request")?;

    let (read_half, _) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut response = Vec::new();
    let bytes = timeout(CONTROL_IO_TIMEOUT, reader.read_until(b'\n', &mut response))
        .await
        .context("timed out waiting for control response")?
        .context("read control response")?;
    if bytes == 0 {
        return Err(anyhow!(
            "daemon closed control socket without a response frame"
        ));
    }

    let decoded = decode_response(&response).context("decode control response")?;
    Ok(decoded)
}

#[cfg(unix)]
async fn connect_with_retry(socket: &str) -> anyhow::Result<UnixStream> {
    let deadline = Instant::now() + CONNECT_RETRY_WINDOW;

    loop {
        match timeout(CONTROL_IO_TIMEOUT, UnixStream::connect(socket)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(err)) => {
                if should_retry_connect(&err) && Instant::now() < deadline {
                    sleep(CONNECT_RETRY_DELAY).await;
                    continue;
                }
                return Err(err).with_context(|| format!("connect to daemon socket {socket}"));
            }
            Err(_) => {
                return Err(anyhow!("timed out connecting to daemon control socket"));
            }
        }
    }
}

fn should_retry_connect(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::NotFound
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::AddrNotAvailable
            | std::io::ErrorKind::WouldBlock
    )
}
