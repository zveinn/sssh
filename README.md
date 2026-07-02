# gossh (Rust)

A small Rust wrapper around the real `ssh` binary.

- Fetches SSH private keys from S3 (or MinIO) using the official `minio` crate.
- Supports age-encrypted keys (prompts for passphrase).
- Never writes the private key to disk — uses Linux `memfd_create`.
- Hands the key to `ssh` via `/proc/self/fd/3`.
- Proper TTY / session / controlling terminal handover so you get a real interactive ssh.

## Build

```bash
cargo build --release
./target/release/gossh ...
```

## Config

Place at `~/.secrets/gossh/config.yaml`:

```yaml
endpoint: "https://s3.example.com"   # MinIO or S3-compatible endpoint
bucket: "my-ssh-keys"
minio_user: "my-minio-user"          # MinIO access key / username (password is prompted)

aliases:
  machine1:
    target: "ec2-user@10.0.0.42"
    s3_key: "machine1"   # optional. If omitted, defaults to the alias name (good for flat storage)
```

Copy `config.yaml.example` as a starting point.

## Credentials

- The MinIO **username** (access key) is taken from `minio_user` in the config file.
- You will be **prompted** for the MinIO **password** (secret key) when fetching a key.
- This avoids storing the secret in the config or environment.

## Usage

```bash
./gossh machine1
./gossh machine1 -L 8080:localhost:8080
./gossh prod -- whoami
```

You can also pass a raw target if no alias matches:

```bash
./gossh ec2-user@1.2.3.4
```

## Preparing an encrypted key

```bash
age -p -o id_ed25519.age < ~/.ssh/id_ed25519
mc cp id_ed25519.age storage/secrets/machine1
# or with MinIO client
```

## Notes

- Linux only (memfd + /proc/self/fd + setsid/TIOCSCTTY).
- The real `ssh` is executed, so you keep full compatibility.
- The binary is currently quite large due to tokio + reqwest + minio + age.

## Development

```bash
cargo run -- machine1
cargo check
```