use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};

use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use minio::s3::creds::StaticProvider;
use minio::s3::http::BaseUrl;
use minio::s3::segmented_bytes::SegmentedBytes;
use minio::s3::types::S3Api;
use minio::s3::MinioClient;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// Encrypted blob layout: MAGIC || salt || nonce || ciphertext. The salt is
// random per key and stored in the blob, so every key derives an independent
// encryption key. The magic both versions the format and catches "this object
// was never encrypted".
const MAGIC: &[u8] = b"sssh2";
const NONCE_LEN: usize = 12;
const SALT_LEN: usize = 16;

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    endpoint: String,
    bucket: String,
    #[serde(default)]
    minio_user: String,
    #[serde(default)]
    minio_secret: String,
    #[serde(default)]
    aliases: HashMap<String, Alias>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Alias {
    target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    s3_key: Option<String>,
}

fn config_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;
    Ok(home.join(".secrets/sssh/config.yaml"))
}

fn load_config() -> Result<Config, String> {
    let path = config_path()?;

    if !path.exists() {
        return Err(format!(
            "config file not found at {}\nCreate it or pass a direct user@host (e.g. user@1.2.3.4)",
            path.display()
        ));
    }

    let data = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let cfg: Config = serde_yaml::from_str(&data).map_err(|e| e.to_string())?;
    Ok(cfg)
}

// The config now carries the MinIO secret key, so keep it out of other
// users' reach.
fn save_config(cfg: &Config) -> Result<(), String> {
    let path = config_path()?;
    let data = serde_yaml::to_string(cfg).map_err(|e| e.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("failed to open {}: {}", path.display(), e))?;
    // mode() above only applies on create; tighten pre-existing files too
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to chmod {}: {}", path.display(), e))?;
    file.write_all(data.as_bytes())
        .map_err(|e| format!("failed to write {}: {}", path.display(), e))?;
    Ok(())
}

fn resolve_target(cfg: &Config, name: &str) -> Result<(String, String), String> {
    if let Some(alias) = cfg.aliases.get(name) {
        // If s3_key is not specified, default to the alias name itself (useful for flat bucket storage)
        let key = alias.s3_key.clone().unwrap_or_else(|| name.to_string());
        return Ok((alias.target.clone(), key));
    }

    Err(format!(
        "unknown alias '{}' and it does not look like a direct SSH target",
        name
    ))
}

// aliases are stored as user@host[:port]; ssh only understands the port
// via the ssh:// URI form, so wrap when a port is present.
fn normalize_target(target: &str) -> String {
    if target.starts_with("ssh://") {
        return target.to_string();
    }
    if let Some(at) = target.rfind('@') {
        if target[at + 1..].matches(':').count() == 1 {
            return format!("ssh://{}", target);
        }
    }
    target.to_string()
}

// Argon2id parameters. Well above the OWASP floor (19 MiB / t=2), since these
// protect long-lived SSH private keys: 64 MiB of memory, 3 passes.
fn argon2_current() -> Result<argon2::Argon2<'static>, String> {
    let params = argon2::Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| format!("invalid argon2 params: {}", e))?;
    Ok(argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    ))
}

fn derive_key(argon: &argon2::Argon2, password: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("argon2 key derivation failed: {}", e))?;
    Ok(key)
}

fn encrypt_key(plaintext: &[u8], password: &str) -> Result<Vec<u8>, String> {
    // Fresh random salt per key: independent derived key, no shared-key or
    // nonce-reuse-across-keys exposure, and nothing to precompute offline.
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let argon = argon2_current()?;
    let mut key = derive_key(&argon, password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("encryption failed: {}", e));
    key.zeroize();
    let ciphertext = ciphertext?;

    let mut blob = Vec::with_capacity(MAGIC.len() + SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

fn decrypt_with(
    argon: &argon2::Argon2,
    password: &str,
    salt: &[u8],
    nonce: &Nonce,
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let mut key = derive_key(argon, password, salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "decryption failed: wrong password or corrupted key data".to_string());
    key.zeroize();
    plaintext
}

fn decrypt_key(blob: &[u8], password: &str) -> Result<Vec<u8>, String> {
    // MAGIC || salt || nonce || ciphertext
    let header = MAGIC.len() + SALT_LEN + NONCE_LEN;
    if blob.len() < header || &blob[..MAGIC.len()] != MAGIC {
        return Err(
            "object is not an sssh-encrypted key (re-upload it with `sssh add-key`)".to_string(),
        );
    }
    let salt = &blob[MAGIC.len()..MAGIC.len() + SALT_LEN];
    let nonce = Nonce::from_slice(&blob[MAGIC.len() + SALT_LEN..header]);
    let ciphertext = &blob[header..];
    decrypt_with(&argon2_current()?, password, salt, nonce, ciphertext)
}

fn make_client(cfg: &Config) -> Result<MinioClient, String> {
    if cfg.minio_user.trim().is_empty() || cfg.minio_secret.trim().is_empty() {
        return Err("minio_user and minio_secret must be set in config.yaml".to_string());
    }
    let base_url: BaseUrl = cfg
        .endpoint
        .parse()
        .map_err(|e| format!("invalid S3 endpoint URL: {}", e))?;
    let provider = StaticProvider::new(&cfg.minio_user, &cfg.minio_secret, None);
    MinioClient::new(base_url, Some(provider), None, None)
        .map_err(|e| format!("failed to create MinIO client: {}", e))
}

async fn fetch_key(cfg: &Config, key: &str) -> Result<Vec<u8>, String> {
    let client = make_client(cfg)?;

    let resp = client
        .get_object(
            &cfg.bucket,
            minio::s3::types::ObjectKey::new(key).map_err(|e| format!("{}", e))?,
        )
        .map_err(|e| format!("minio get_object failed: {}", e))?
        .build()
        .send()
        .await
        .map_err(|e| format!("failed to get object s3://{}/{}: {}", cfg.bucket, key, e))?;

    let data = resp
        .into_bytes()
        .await
        .map_err(|e| format!("failed to read object body: {}", e))?;

    Ok(data.to_vec())
}

async fn upload_key(cfg: &Config, key: &str, blob: Vec<u8>) -> Result<(), String> {
    let client = make_client(cfg)?;

    client
        .put_object(
            &cfg.bucket,
            minio::s3::types::ObjectKey::new(key).map_err(|e| format!("{}", e))?,
            SegmentedBytes::from(bytes::Bytes::from(blob)),
        )
        .map_err(|e| format!("minio put_object failed: {}", e))?
        .build()
        .send()
        .await
        .map_err(|e| format!("failed to put object s3://{}/{}: {}", cfg.bucket, key, e))?;

    Ok(())
}

fn prompt_password(prompt: &str) -> Result<String, String> {
    use std::io::IsTerminal;
    eprint!("{}", prompt);
    let res = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("")
    } else {
        // no tty (piped/scripted use): read one line from stdin instead
        rpassword::read_password_with_config(
            rpassword::ConfigBuilder::new()
                .input_reader(std::io::stdin())
                .output_writer(std::io::stderr())
                .build(),
        )
    };
    res.map_err(|e| format!("failed to read password: {}", e))
}

async fn add_key(alias: &str, target: &str, s3_key: &str, key_path: &str) -> Result<(), String> {
    if alias == "add-key" {
        return Err("alias 'add-key' is reserved (it is the add-key command)".to_string());
    }

    let mut cfg = load_config()?;

    let mut plaintext = std::fs::read(key_path)
        .map_err(|e| format!("failed to read key file {}: {}", key_path, e))?;

    let mut password = prompt_password("Enter encryption password: ")?;
    let mut confirm = prompt_password("Confirm encryption password: ")?;
    if password != confirm {
        password.zeroize();
        confirm.zeroize();
        plaintext.zeroize();
        return Err("passwords do not match".to_string());
    }
    confirm.zeroize();

    let blob = encrypt_key(&plaintext, &password);
    password.zeroize();
    plaintext.zeroize();
    let blob = blob?;

    eprintln!("Uploading encrypted key to s3://{}/{}...", cfg.bucket, s3_key);
    upload_key(&cfg, s3_key, blob).await?;

    if cfg.aliases.contains_key(alias) {
        eprintln!("note: replacing existing alias '{}'", alias);
    }
    cfg.aliases.insert(
        alias.to_string(),
        Alias {
            target: target.to_string(),
            s3_key: Some(s3_key.to_string()),
        },
    );
    save_config(&cfg)?;

    eprintln!("Added alias '{}' -> {} (key: {})", alias, target, s3_key);
    Ok(())
}

fn disable_core_dumps() -> Result<(), String> {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) } != 0 {
        return Err(format!(
            "failed to disable core dumps: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn create_key_memfd(key: &[u8]) -> Result<File, String> {
    // Anonymous in-memory file: never touches the filesystem, vanishes when
    // the last fd to it is closed. ssh reads it via /proc/<our-pid>/fd/N, so
    // the fd only needs to live in this process (CLOEXEC keeps it out of ssh).
    let fd = unsafe { libc::memfd_create(c"sssh-key".as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(format!(
            "memfd_create failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };

    // memfds are created 0777; ssh refuses identity files readable by others
    if unsafe { libc::fchmod(fd, 0o600) } != 0 {
        return Err(format!(
            "fchmod on memfd failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    file.write_all(key)
        .map_err(|e| format!("failed to write key to memfd: {}", e))?;

    Ok(file)
}

// The memfd is closed the moment ssh reports successful authentication:
// ssh runs our LocalCommand (which fires only post-auth) and that sends us
// SIGUSR1. Closing the last fd releases the key from kernel memory while
// the session is still running.
static KEY_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn close_key_fd(_sig: libc::c_int) {
    let fd = KEY_FD.swap(-1, Ordering::SeqCst);
    if fd >= 0 {
        // close(2) is async-signal-safe
        unsafe {
            libc::close(fd);
        }
    }
}

fn install_key_release_handler(fd: RawFd) -> Result<(), String> {
    KEY_FD.store(fd, Ordering::SeqCst);

    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    sa.sa_sigaction = close_key_fd as *const () as usize;
    sa.sa_flags = libc::SA_RESTART;
    if unsafe { libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()) } != 0 {
        return Err(format!(
            "failed to install SIGUSR1 handler: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn exec_ssh(target: &str, key_fd: RawFd, extra_args: &[String]) -> Result<(), String> {
    let ssh_path = which::which("ssh").unwrap_or_else(|_| std::path::PathBuf::from("/usr/bin/ssh"));

    let mut cmd = Command::new(ssh_path);
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    // The key exists only as a memfd held open by this (sssh) process. ssh
    // closes all inherited fds above stderr at startup (closefrom), so it
    // cannot see the fd as /proc/self/fd/N — instead point it at our copy,
    // which stays open for the whole session. IdentitiesOnly pins ssh to
    // exactly this key, and hiding the user's agent keeps other identities
    // from being offered.
    cmd.arg("-o").arg("IdentitiesOnly=yes");
    cmd.arg("-i")
        .arg(format!("/proc/{}/fd/{}", std::process::id(), key_fd));
    cmd.env_remove("SSH_AUTH_SOCK");

    // LocalCommand runs after authentication succeeds — tell sssh to
    // release the key (see close_key_fd)
    cmd.arg("-o").arg("PermitLocalCommand=yes");
    cmd.arg("-o")
        .arg(format!("LocalCommand=kill -USR1 {}", std::process::id()));

    // No setsid/TIOCSCTTY: ssh must stay in our (foreground) process group
    // so the kernel delivers SIGWINCH to it on terminal resize — otherwise
    // window-size changes never reach the remote side.

    cmd.arg(target);
    cmd.args(extra_args);

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to execute ssh: {}", e))?;

    let status = child
        .wait()
        .map_err(|e| format!("failed to wait for ssh: {}", e))?;

    if let Some(code) = status.code() {
        std::process::exit(code);
    } else {
        // Killed by signal
        std::process::exit(128 + 9); // common convention
    }
}

#[tokio::main]
async fn main() -> Result<(), String> {
    disable_core_dumps()?;

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage: {} <alias> [ssh options...]\n       {} add-key <alias> <user@host[:port]> <s3_keyname> <path_to_ssh_key>",
            args[0], args[0]
        );
        std::process::exit(2);
    }

    if args[1] == "add-key" {
        if args.len() != 6 {
            eprintln!(
                "Usage: {} add-key <alias> <user@host[:port]> <s3_keyname> <path_to_ssh_key>",
                args[0]
            );
            std::process::exit(2);
        }
        return add_key(&args[2], &args[3], &args[4], &args[5]).await;
    }

    let alias = &args[1];
    let extra_args: Vec<String> = args[2..].to_vec();
    let cfg = load_config()?;
    let (target, s3_key) = resolve_target(&cfg, alias)?;

    eprintln!("Fetching key {} from S3...", s3_key);
    let blob = fetch_key(&cfg, &s3_key).await?;

    let mut password = prompt_password(&format!("Enter encryption password for {}: ", alias))?;
    let data = decrypt_key(&blob, &password);
    password.zeroize();
    let mut data = data?;

    let key_file = create_key_memfd(&data)?;
    data.zeroize();

    // Hand ownership of the fd to the signal handler: it is closed on
    // SIGUSR1 (post-auth), or by the kernel when sssh exits.
    let key_fd = key_file.into_raw_fd();
    install_key_release_handler(key_fd)?;

    exec_ssh(&normalize_target(&target), key_fd, &extra_args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_recovers_plaintext() {
        let plaintext = b"-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n";
        let blob = encrypt_key(plaintext, "correct horse").unwrap();
        assert_eq!(&blob[..MAGIC.len()], MAGIC);
        let out = decrypt_key(&blob, "correct horse").unwrap();
        assert_eq!(out, plaintext);
    }

    #[test]
    fn wrong_password_fails() {
        let blob = encrypt_key(b"key material", "right").unwrap();
        assert!(decrypt_key(&blob, "wrong").is_err());
    }

    #[test]
    fn each_encryption_uses_a_fresh_salt() {
        let a = encrypt_key(b"same input", "same password").unwrap();
        let b = encrypt_key(b"same input", "same password").unwrap();
        let salt_a = &a[MAGIC.len()..MAGIC.len() + SALT_LEN];
        let salt_b = &b[MAGIC.len()..MAGIC.len() + SALT_LEN];
        assert_ne!(salt_a, salt_b, "salt must be random per key");
        // Different salt (and nonce) => different ciphertext for identical input.
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_unknown_magic() {
        assert!(decrypt_key(b"not-an-sssh-blob at all", "pw").is_err());
    }

    #[test]
    fn rejects_truncated_blob() {
        let blob = encrypt_key(b"x", "pw").unwrap();
        // Chop into the header (salt/nonce) region.
        assert!(decrypt_key(&blob[..MAGIC.len() + 4], "pw").is_err());
    }
}
