# sssh

SSH with private keys stored encrypted in S3. Keys are encrypted client-side
(argon2id + ChaCha20-Poly1305) before upload, fetched and decrypted in memory
at connect time, and freed the moment authentication succeeds. Nothing is ever
written to disk and the bucket only ever sees ciphertext.

## How it works

1. `sssh add-key` encrypts a private key with a key derived from your
   password (argon2id with a random per-key salt) and uploads it to an S3
   bucket (MinIO or any S3-compatible store). Each key gets its own salt,
   stored alongside the ciphertext, so no two keys ever share a derived key.
2. `sssh <alias>` fetches the encrypted key, prompts for your password and
   decrypts it in memory.
3. The key goes into an anonymous in-memory file (`memfd_create`) and
   `ssh -i` is pointed at it. It never touches the filesystem.
4. As soon as ssh authenticates, the in-memory key is destroyed. Your session
   keeps running normally.

## Install

```bash
cargo build --release
sudo cp target/release/sssh /usr/local/bin/
```

Or grab a binary from the releases page.

## Configure

Create `~/.secrets/sssh/config.yaml` (see `config.yaml.example`):

```yaml
endpoint: "https://s3.example.com"   # S3 or MinIO endpoint
bucket: "ssh-keys"                   # bucket holding the encrypted keys
minio_user: "myuser"                 # S3 access key
minio_secret: "mysecret"             # S3 secret key
```

Keep the file `chmod 600` — it holds the S3 secret. Aliases are added by
`add-key`. The argon2 salt lives inside each encrypted key, not in the config.

## Use

Add a key (encrypts it locally, uploads it, creates the alias):

```bash
sssh add-key myserver root@203.0.113.10 myserver ~/.ssh/id_ed25519
```

Connect:

```bash
sssh myserver
sssh myserver -L 8080:localhost:8080   # extra args are passed to ssh
```

You are prompted for the encryption password on both. The alias name
`add-key` is reserved.

## Notes

- Linux only.
- Runs your real `ssh`, so options, config and behavior all work as usual.
- To watch the key appear and disappear from memory:

  ```bash
  watch -n 0.2 "find /proc/[0-9]*/fd -lname '/memfd:sssh-key*' 2>/dev/null"
  ```
