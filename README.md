# ssh-agent-proxy

An SSH agent proxy that filters identities based on the requesting process's working directory. Point `IdentityAgent` in your SSH config at this proxy's socket and forward requests to an upstream agent (e.g. 1Password) while only exposing keys that match the process directory.

## Quick start

Create a config file (e.g. `~/.config/ssh-agent-proxy.toml`):

```toml
socket = "~/.ssh/agent-proxy.sock"
upstream = "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"

[[match]]
fingerprint = "SHA256:…"
directories = ["~/work", "~/business"]

[[match]]
fingerprint = "SHA256:…"
directories = ["~/personal", "~/open_source"]
```

Build and install the binary:

```sh
make install
```

Use the proxy in `~/.ssh/config`:

```
Host *
    IdentityAgent ~/.ssh/agent-proxy.sock
```
