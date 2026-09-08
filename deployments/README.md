# Deployment profiles

Reusable code and generic block-list defaults live outside this directory. Each
installation keeps its topology and identities in one deployment profile.

```bash
cp -R deployments/example deployments/local
```

Edit `deployments/local/deployment.env`, `proxy-hosts.conf`, and `devices.list`.
The `local` profile is ignored by Git. Select another profile by exporting
`SQUID_DEPLOYMENT_DIR=/absolute/path/to/profile` before running a management,
deployment, or diagnostic script.

`deployment.env` owns host addresses, SSH users, Docker paths and network,
container names and images, proxy/WebUI ports, accepted CIDRs, administrator
client IPs, Squid DNS resolvers, remote diagnostic defaults, and the CA identity.
`SQUID_DNS_SERVERS` defaults to `8.8.8.8` when omitted and accepts multiple
space-separated resolver IPs.

Keep generated CA files in `deployments/local/certs/`. Never commit the private
key. Block lists remain shareable defaults under `block-lists/`; set
`BLOCKLIST_DIR` in `deployment.env` when an installation needs private lists.

This layout prevents future commits from mixing deployment data into reusable
code. Existing Git history still contains earlier values and must be rewritten
or replaced before publishing the repository publicly.

## QNAP Container Station & Macvlan (`qnet`) Architecture

On QNAP NAS hosts, Docker is managed by Container Station:
- **Binary**: Located at `/share/CACHEDEV1_DATA/.qpkg/container-station/bin/docker`.
- **Network Driver (`qnet`)**: QNAP provides a customized macvlan driver (`qnet`) that binds directly to a physical adapter (e.g. `eth0`), giving each container its own dedicated LAN IP in the local subnet (`192.168.0.0/18`).
- **Container Separation**:
  - `squid-proxy`: Listens on its own IP (e.g. `192.168.1.90`) for forward proxy (`3128`), transparent HTTP (`3129`), and transparent HTTPS (`3130`).
  - `squid-webui`: Listens on its own IP (e.g. `192.168.1.91:3131`), mounts persistent configs/logs/blocklists, and mounts `/var/run/docker.sock` to send SIGHUP reload signals to `squid-proxy` without container restarts.
  - `pihole-*`: Upstream DNS instances run on dedicated IPs (e.g. `192.168.1.81` for `pihole-squid`), providing domain resolution and upstream ad-blocking directly to Squid.

