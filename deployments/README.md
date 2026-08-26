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
client IPs, remote diagnostic defaults, and the CA identity.

Keep generated CA files in `deployments/local/certs/`. Never commit the private
key. Block lists remain shareable defaults under `block-lists/`; set
`BLOCKLIST_DIR` in `deployment.env` when an installation needs private lists.

This layout prevents future commits from mixing deployment data into reusable
code. Existing Git history still contains earlier values and must be rewritten
or replaced before publishing the repository publicly.
