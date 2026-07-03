use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};

use minio::s3::creds::StaticProvider;
use minio::s3::http::BaseUrl;
use minio::s3::types::S3Api;
use minio::s3::MinioClient;
use nix::unistd::setsid;
use serde::Deserialize;
use zeroize::Zeroize;

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

fn load_config() -> Result<Config, String> {
    let home = dirs::home_dir().ok_or_else(|| "could not determine home directory".to_string())?;
    let path = home.join(".secrets/gossh/config.yaml");

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

async fn fetch_key(cfg: &Config, key: &str, secret_key: &str) -> Result<Vec<u8>, String> {
    let base_url: BaseUrl = cfg
        .endpoint
        .parse()
        .map_err(|e| format!("invalid S3 endpoint URL: {}", e))?;
    let provider = StaticProvider::new(&cfg.minio_user, secret_key, None);

    eprint!("{}\n", base_url.to_url_string());
    let client = MinioClient::new(base_url, Some(provider), None, None)
        .map_err(|e| format!("failed to create MinIO client: {}", e))?;

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
    let fd = unsafe { libc::memfd_create(c"gossh-key".as_ptr(), libc::MFD_CLOEXEC) };
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

    // The key exists only as a memfd held open by this (gossh) process. ssh
    // closes all inherited fds above stderr at startup (closefrom), so it
    // cannot see the fd as /proc/self/fd/N — instead point it at our copy,
    // which stays open for the whole session. IdentitiesOnly pins ssh to
    // exactly this key, and hiding the user's agent keeps other identities
    // from being offered.
    cmd.arg("-o").arg("IdentitiesOnly=yes");
    cmd.arg("-i")
        .arg(format!("/proc/{}/fd/{}", std::process::id(), key_fd));
    cmd.env_remove("SSH_AUTH_SOCK");

    // LocalCommand runs after authentication succeeds — tell gossh to
    // release the key (see close_key_fd)
    cmd.arg("-o").arg("PermitLocalCommand=yes");
    cmd.arg("-o")
        .arg(format!("LocalCommand=kill -USR1 {}", std::process::id()));

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
        eprintln!("Usage: {} <alias|user@host> [ssh options...]", args[0]);
        std::process::exit(2);
    }

    let alias = &args[1];
    let extra_args: Vec<String> = args[2..].to_vec();
    let cfg = load_config()?;
    let (target, s3_key) = resolve_target(&cfg, alias)?;

    if cfg.minio_user.trim().is_empty() {
        return Err(
            "minio_user is not set in config.yaml (required when using S3 keys)".to_string(),
        );
    }

    eprint!("Enter MinIO password for {}: ", &cfg.minio_user);
    let mut secret_key = rpassword::prompt_password("")
        .map_err(|e| format!("failed to read MinIO password: {}", e))?;

    eprintln!("Fetching key {} from S3...", s3_key);

    let mut data = fetch_key(&cfg, &s3_key, &secret_key).await?;
    secret_key.zeroize();

    let key_file = create_key_memfd(&data)?;
    data.zeroize();

    // Hand ownership of the fd to the signal handler: it is closed on
    // SIGUSR1 (post-auth), or by the kernel when gossh exits.
    let key_fd = key_file.into_raw_fd();
    install_key_release_handler(key_fd)?;

    exec_ssh(&target, key_fd, &extra_args)
}
