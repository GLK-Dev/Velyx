use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use snow::{Builder, params::NoiseParams};
use tokio::net::UdpSocket;

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        print_usage();
        bail!("not enough arguments");
    }

    let mode = args[1].as_str();
    let bind_addr = args[2].as_str();

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let peer_id = hex::encode(signing_key.verifying_key().as_bytes());
    println!("Velyx node started");
    println!("Peer ID (ed25519): {peer_id}");

    match mode {
        "responder" => run_responder(bind_addr).await,
        "initiator" => {
            if args.len() < 4 {
                print_usage();
                bail!("initiator mode needs a remote address");
            }
            run_initiator(bind_addr, args[3].as_str()).await
        }
        _ => {
            print_usage();
            bail!("unknown mode: {mode}")
        }
    }
}

fn print_usage() {
    println!("Usage:");
    println!("  velyx responder <bind_addr>");
    println!("  velyx initiator <bind_addr> <remote_addr>");
    println!("Examples:");
    println!("  velyx responder 0.0.0.0:9000");
    println!("  velyx initiator 0.0.0.0:0 127.0.0.1:9000");
}

fn noise_private_key() -> Result<Vec<u8>> {
    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .context("failed to parse noise pattern")?;
    let keypair = Builder::new(params)
        .generate_keypair()
        .context("failed to generate noise static keypair")?;
    Ok(keypair.private)
}

async fn run_responder(bind_addr: &str) -> Result<()> {
    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind responder socket on {bind_addr}"))?;
    println!("Responder listening on {bind_addr}");

    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .context("failed to parse noise pattern")?;
    let static_key = noise_private_key()?;

    let mut hs = Builder::new(params)
        .local_private_key(&static_key)
        .build_responder()
        .context("failed to build responder state")?;

    let mut in_buf = [0u8; 2048];
    let mut out_buf = [0u8; 2048];

    let (len1, remote) = socket
        .recv_from(&mut in_buf)
        .await
        .context("failed to receive handshake message 1")?;
    hs.read_message(&in_buf[..len1], &mut out_buf)
        .context("failed to parse handshake message 1")?;
    println!("Handshake msg1 received from {remote}");

    let len2 = hs
        .write_message(&[], &mut out_buf)
        .context("failed to write handshake message 2")?;
    socket
        .send_to(&out_buf[..len2], remote)
        .await
        .context("failed to send handshake message 2")?;

    let (len3, remote2) = socket
        .recv_from(&mut in_buf)
        .await
        .context("failed to receive handshake message 3")?;
    if remote2 != remote {
        bail!("handshake source mismatch: expected {remote}, got {remote2}");
    }
    hs.read_message(&in_buf[..len3], &mut out_buf)
        .context("failed to parse handshake message 3")?;
    println!("Secure channel established with {remote}");

    let mut transport = hs
        .into_transport_mode()
        .context("failed to switch to transport mode")?;

    let (enc_len, remote3) = socket
        .recv_from(&mut in_buf)
        .await
        .context("failed to receive encrypted payload")?;
    if remote3 != remote {
        bail!("payload source mismatch: expected {remote}, got {remote3}");
    }

    let msg_len = transport
        .read_message(&in_buf[..enc_len], &mut out_buf)
        .context("failed to decrypt payload")?;
    let incoming = String::from_utf8_lossy(&out_buf[..msg_len]);
    println!("Decrypted payload: {incoming}");

    let reply = b"velyx-pong";
    let enc_reply_len = transport
        .write_message(reply, &mut out_buf)
        .context("failed to encrypt response")?;
    socket
        .send_to(&out_buf[..enc_reply_len], remote)
        .await
        .context("failed to send encrypted response")?;

    println!("Encrypted response sent");
    Ok(())
}

async fn run_initiator(bind_addr: &str, remote_addr: &str) -> Result<()> {
    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind initiator socket on {bind_addr}"))?;
    println!("Initiator bound on {bind_addr}, remote: {remote_addr}");

    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .context("failed to parse noise pattern")?;
    let static_key = noise_private_key()?;

    let mut hs = Builder::new(params)
        .local_private_key(&static_key)
        .build_initiator()
        .context("failed to build initiator state")?;

    let mut in_buf = [0u8; 2048];
    let mut out_buf = [0u8; 2048];

    let len1 = hs
        .write_message(&[], &mut out_buf)
        .context("failed to write handshake message 1")?;
    socket
        .send_to(&out_buf[..len1], remote_addr)
        .await
        .context("failed to send handshake message 1")?;

    let (len2, from2) = socket
        .recv_from(&mut in_buf)
        .await
        .context("failed to receive handshake message 2")?;
    if from2.to_string() != remote_addr {
        bail!("handshake source mismatch: expected {remote_addr}, got {from2}");
    }
    hs.read_message(&in_buf[..len2], &mut out_buf)
        .context("failed to parse handshake message 2")?;

    let len3 = hs
        .write_message(&[], &mut out_buf)
        .context("failed to write handshake message 3")?;
    socket
        .send_to(&out_buf[..len3], remote_addr)
        .await
        .context("failed to send handshake message 3")?;
    println!("Secure channel established with {remote_addr}");

    let mut transport = hs
        .into_transport_mode()
        .context("failed to switch to transport mode")?;

    let payload = b"velyx-ping";
    let enc_len = transport
        .write_message(payload, &mut out_buf)
        .context("failed to encrypt payload")?;
    socket
        .send_to(&out_buf[..enc_len], remote_addr)
        .await
        .context("failed to send encrypted payload")?;

    let (resp_len, from3) = socket
        .recv_from(&mut in_buf)
        .await
        .context("failed to receive encrypted response")?;
    if from3.to_string() != remote_addr {
        bail!("response source mismatch: expected {remote_addr}, got {from3}");
    }
    let plain_len = transport
        .read_message(&in_buf[..resp_len], &mut out_buf)
        .context("failed to decrypt response")?;
    let response = String::from_utf8_lossy(&out_buf[..plain_len]);
    println!("Decrypted response: {response}");

    Ok(())
}
