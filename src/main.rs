use std::collections::HashMap;
use std::io::{Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use minio::s3::creds::StaticProvider;
use minio::s3::http::BaseUrl;
use minio::s3::types::S3Api;
use minio::s3::MinioClient;
use nix::unistd::setsid;
use serde::Deserialize;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Deserialize)]
struct Config {
    endpoint: String,
    bucket: String,
    #[serde(default)]
    minio_user: String,
    aliases: HashMap<String, Alias>,
}

#[derive(Debug, Deserialize)]
struct Alias {
    target: String,
    #[serde(default)]
    s3_key: Option<String>,
}

fn load_config() -> Result<Config> {
    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    let path = home.join(".secrets/gossh/config.yaml");

    if !path.exists() {
        return Err(format!(
            "config file not found at {}\nCreate it or pass a direct user@host (e.g. user@1.2.3.4)",
            path.display()
        ).into());
    }

    let data = std::fs::read_to_string(&path)?;
    let cfg: Config = serde_yaml::from_str(&data)?;
    Ok(cfg)
}

fn resolve_target(cfg: &Config, name: &str) -> Result<(String, Option<String>)> {
    if let Some(alias) = cfg.aliases.get(name) {
        // If s3_key is not specified, default to the alias name itself (useful for flat bucket storage)
        let key = alias.s3_key.clone().unwrap_or_else(|| name.to_string());
        return Ok((alias.target.clone(), Some(key)));
    }

    // Allow direct targets like user@ip or host
    if name.contains('@') || name.contains('.') || name.contains(':') {
        return Ok((name.to_string(), None));
    }

    Err(format!("unknown alias '{}' and it does not look like a direct SSH target", name).into())
}

async fn fetch_key(
    endpoint: &str,
    bucket: &str,
    key: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<Vec<u8>> {
    let base_url: BaseUrl = endpoint.parse().map_err(|e| format!("invalid S3 endpoint URL: {}", e))?;
    let provider = StaticProvider::new(access_key, secret_key, None);

    let client = MinioClient::new(base_url, Some(provider), None, None)
        .map_err(|e| format!("failed to create MinIO client: {}", e))?;

    let resp = client
        .get_object(bucket, minio::s3::types::ObjectKey::new(key).map_err(|e| format!("{}", e))?)?
        .build()
        .send()
        .await
        .map_err(|e| format!("failed to get object s3://{}/{}: {}", bucket, key, e))?;

    let data = resp
        .into_bytes()
        .await
        .map_err(|e| format!("failed to read object body: {}", e))?;

    Ok(data.to_vec())
}

fn maybe_decrypt_age(data: Vec<u8>) -> Result<Vec<u8>> {
    const AGE_MAGIC: &[u8] = b"age-encryption.org/";

    if !data.starts_with(AGE_MAGIC) {
        return Ok(data);
    }

    // Prompt on stderr
    eprint!("Enter passphrase for encrypted key: ");
    let passphrase = rpassword::prompt_password("")
        .map_err(|e| format!("failed to read passphrase: {}", e))?;

    let decryptor = match age::Decryptor::new(&data[..])? {
        age::Decryptor::Passphrase(d) => d,
        _ => return Err("not a passphrase-encrypted age file".into()),
    };

    let mut decrypted = vec![];
    let mut reader = decryptor.decrypt(&age::secrecy::Secret::new(passphrase), None)?;
    reader.read_to_end(&mut decrypted)?;

    Ok(decrypted)
}

fn create_key_file(key: &[u8]) -> Result<(String, std::fs::File)> {
    // Use /dev/shm (tmpfs) so the key lives only in memory, no disk.
    // This is much more compatible with ssh's file handling than /proc/self/fd.
    let path = format!("/dev/shm/gossh-key-{}", std::process::id());

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("failed to create key file at {}: {}", path, e))?;

    file.write_all(key)?;
    file.seek(std::io::SeekFrom::Start(0))?;

    // We keep the File open so the content stays alive even after we unlink.
    Ok((path, file))
}

fn exec_ssh(target: &str, key_file: Option<(String, std::fs::File)>, extra_args: &[String]) -> Result<()> {
    let ssh_path = which::which("ssh").unwrap_or_else(|_| std::path::PathBuf::from("/usr/bin/ssh"));

    let mut cmd = Command::new(ssh_path);
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let key_path = if let Some((path, _file)) = &key_file {
        // Pass a normal path. ssh is much happier with a real file path
        // than /proc/self/fd/N (especially with its internal checks).
        cmd.arg("-i").arg(path);
        cmd.arg("-o").arg("IdentitiesOnly=yes");
        Some(path.clone())
    } else {
        None
    };

    // Set up controlling terminal etc.
    unsafe {
        cmd.pre_exec(|| {
            let _ = setsid();

            if let Ok(tty) = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
            {
                let _ = libc::ioctl(tty.as_raw_fd(), libc::TIOCSCTTY, 0);
            }

            Ok(())
        });
    }

    cmd.arg(target);
    cmd.args(extra_args);

    // We keep the File in scope so the content in /dev/shm stays alive.
    // We will unlink after ssh has had a chance to open it.
    let _keep_file = key_file;

    let status = cmd.status().map_err(|e| format!("failed to execute ssh: {}", e))?;

    // Now that ssh has started and opened the file, clean up the tmpfs entry.
    if let Some(p) = key_path {
        let _ = std::fs::remove_file(&p);
    }

    if let Some(code) = status.code() {
        std::process::exit(code);
    } else {
        // Killed by signal
        std::process::exit(128 + 9); // common convention
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <alias|user@host> [ssh options...]", args[0]);
        std::process::exit(2);
    }

    let alias = &args[1];
    let extra_args: Vec<String> = args[2..].to_vec();

    // Try to load config (optional if using direct target)
    let cfg = load_config().ok();

    let (target, s3_key) = if let Some(ref c) = cfg {
        resolve_target(c, alias)?
    } else {
        // No config file - treat first arg as direct target
        if alias.contains('@') || alias.contains('.') {
            (alias.clone(), None)
        } else {
            return Err(format!(
                "no config file found at ~/.secrets/gossh/config.yaml and '{}' does not look like a valid SSH target (user@host or host.name)",
                alias
            ).into());
        }
    };

    let mut key_bytes: Option<Vec<u8>> = None;

    if let Some(ref key_name) = s3_key {
        let cfg = cfg.as_ref().unwrap();

        if cfg.minio_user.trim().is_empty() {
            return Err("minio_user is not set in config.yaml (required when using S3 keys)".into());
        }

        let access_key = &cfg.minio_user;

        eprint!("Enter MinIO password for {}: ", access_key);
        let secret_key = rpassword::prompt_password("")
            .map_err(|e| format!("failed to read MinIO password: {}", e))?;

        eprintln!("Fetching key {} from S3...", key_name);

        let data = fetch_key(&cfg.endpoint, &cfg.bucket, key_name, access_key, &secret_key).await?;
        let decrypted = maybe_decrypt_age(data)?;
        key_bytes = Some(decrypted);
    }

    // Create in-memory (tmpfs) key file if we have one
    let key_file = if let Some(ref kb) = key_bytes {
        Some(create_key_file(kb)?)
    } else {
        None
    };

    // Hand over to real ssh (this will not return on success)
    exec_ssh(&target, key_file, &extra_args)
}