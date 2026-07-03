# sssh

SSH with private keys stored in S3. The key is fetched at connect time, kept
only in memory, and freed the moment authentication succeeds. Nothing is ever
written to disk.

## How it works

1. Fetches the private key for your target from an S3 bucket (MinIO or any
   S3-compatible store). You are prompted for the S3 secret key.
2. Puts the key in an anonymous in-memory file (`memfd_create`) and points
   `ssh -i` at it. It never touches the filesystem.
3. As soon as ssh authenticates, the in-memory key is destroyed. Your session
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
bucket: "ssh-keys"                   # bucket holding the private keys
minio_user: "myuser"                 # access key; secret key is prompted

aliases:
  myserver:
    target: "root@203.0.113.10"      # who/where to ssh into
    s3_key: "myserver"               # object name in the bucket (optional,
                                     # defaults to the alias name)
```

Upload a private key to the bucket under the object name used by the alias.

## Use

```bash
sssh myserver
sssh myserver -L 8080:localhost:8080   # extra args are passed to ssh
```

## Notes

- Linux only.
- Runs your real `ssh`, so options, config and behavior all work as usual.
- To watch the key appear and disappear from memory:

  ```bash
  watch -n 0.2 "find /proc/[0-9]*/fd -lname '/memfd:sssh-key*' 2>/dev/null"
  ```
