# FreeVPS

This repository bootstraps a brand-new overseas Ubuntu server into a working proxy system with:

- `sing-box`
- `VLESS Reality`
- `Hysteria2`
- Cloudflare Worker subscription delivery
- Cloudflare KV-backed per-device subscriptions
- a VPS-local device issuance command: `/root/proxy-issuer`

The bootstrap entrypoint is one script:

```bash
sudo ./bootstrap.sh
```

The script is designed to be idempotent. Running it again should converge the server back to the desired state instead of creating a second parallel deployment.

## What This Repository Installs

After a successful bootstrap run, the target server will have:

- a running `sing-box` service listening on:
  - `443/tcp`
  - `443/udp`
- a Cloudflare Worker bound to your subscription hostname
- a Cloudflare KV namespace for per-device subscription payloads
- a DNS-only proxy hostname pointing to the VPS
- automatic ACME DNS-01 certificate support for the proxy hostname
- a device registry and issuance tool on the VPS

The installer does **not** auto-create your first devices. That is intentional. After install, you decide which devices to issue.

## Architecture Summary

### Proxy ingress

- `proxy.<your-domain>` terminates on the VPS
- `sing-box` serves:
  - `VLESS Reality`
  - `Hysteria2`

### Subscription delivery

- `sub.<your-domain>` is served by a Cloudflare Worker
- per-device subscriptions are stored in Cloudflare KV
- subscription URLs are shaped like:

```text
https://sub.<your-domain>/s/<token>
```

### Device issuance

The VPS-local command:

```bash
/root/proxy-issuer
```

manages:

- device registry in SQLite
- `sing-box` user generation
- per-device subscription rendering
- Worker KV synchronization

### Rules

The system preserves the current rule strategy:

- `mihomo`: `Loyalsoldier/clash-rules`
- `Shadowrocket`: `Johnshall/Shadowrocket-ADBlock-Rules-Forever`

The Worker proxies shared rule endpoints:

- `/rules/<name>.txt`
- `/shadowrocket-rules/<name>.list`

## Supported Target Environment

Target assumptions:

- overseas Ubuntu server
- `systemd`
- `apt`
- root shell access
- domain already managed by Cloudflare

Tested environment:

- Ubuntu 24.04 LTS

## Prerequisites

Before running the bootstrap script, you need:

1. A clean Ubuntu server.
2. A domain already hosted on Cloudflare.
3. Two Cloudflare API tokens:
   - one DNS token
   - one Workers/KV token

You do **not** need to pre-create the proxy or subscription subdomains manually.

## Cloudflare Token Setup

The bootstrap uses two different Cloudflare tokens on purpose.

### 1. DNS token

Purpose:

- create/update the `proxy.<domain>` DNS record
- support ACME DNS-01 certificate automation for `sing-box`

Cloudflare dashboard path:

- `My Profile`
- `API Tokens`
- `Create Token`
- `Create Custom Token`

Recommended token name:

```text
bootstrap-dns-<your-domain>
```

Minimum permissions:

- `Zone` -> `DNS` -> `Edit`
- `Zone` -> `Zone` -> `Read`

Zone resources:

- `Include`
- `Specific zone`
- your target zone only

Notes:

- this token is stored on the VPS in `/etc/proxy-issuer/cloudflare.env`
- it is used by `sing-box` certificate automation and must remain available after install

### 2. Workers/KV token

Purpose:

- deploy/update the Cloudflare Worker
- create/reuse the KV namespace
- write per-device subscription payloads into KV

Cloudflare dashboard path:

- `My Profile`
- `API Tokens`
- `Create Token`
- `Create Custom Token`

Recommended token name:

```text
bootstrap-workers-<your-domain>
```

Minimum permissions:

- `Account` -> `Workers Scripts` -> `Write`
- `Account` -> `Workers KV Storage` -> `Edit`
- `Zone` -> `Zone` -> `Read`

If your account requires it for custom-domain management, also add:

- `Zone` -> `Workers Routes` -> `Write`

Account resources:

- `Include`
- `Specific account`
- the Cloudflare account that owns the zone

Zone resources:

- `Include`
- `Specific zone`
- your target zone only

Notes:

- this token is also stored in `/etc/proxy-issuer/cloudflare.env`
- it is used by bootstrap and by `/root/proxy-issuer` when syncing subscriptions into KV

## Installation

Clone this repository onto the target VPS, then run the bootstrap script as root:

```bash
git clone <your-repo-url>
cd <repo-directory>
sudo ./bootstrap.sh
```

The script will ask for:

- Cloudflare root domain
- proxy subdomain label
- subscription subdomain label
- Cloudflare DNS token
- Cloudflare Workers/KV token
- optional ACME contact email

Example answers:

```text
Cloudflare root domain: example.com
Proxy subdomain label [proxy]: proxy
Subscription subdomain label [sub]: sub
Cloudflare DNS token: ********
Cloudflare Workers/KV token: ********
ACME contact email (optional): you@example.com
```

## What the Bootstrap Script Does

The installer converges the server to the target state in these phases:

1. installs base packages
2. installs Node.js LTS and Wrangler
3. installs `sing-box`
4. discovers your Cloudflare zone and account
5. creates or reuses the Worker KV namespace
6. ensures `proxy.<domain>` points to the VPS and is `DNS only`
7. renders and deploys the Worker
8. renders:
   - `/etc/proxy-issuer/settings.json`
   - `/etc/proxy-issuer/cloudflare.env`
   - `/etc/proxy-issuer/config.base.json`
9. installs:
   - `/root/proxy_issuer.py`
   - `/root/proxy-issuer`
10. applies conservative SSH/UFW hardening
11. renders the initial empty `sing-box` runtime state
12. runs smoke tests

## SSH and Firewall Behavior

The script intentionally keeps password-based SSH available.

It does **not**:

- disable global `PasswordAuthentication`
- disable root password SSH

It does:

- set `X11Forwarding no`
- set `AllowTcpForwarding no`
- set `MaxAuthTries 3`
- converge UFW to:
  - `22/tcp` with `limit`
  - `443/tcp`
  - `443/udp`

This is a deliberate compromise so bootstrap does not accidentally lock you out of a fresh server that still depends on password login.

## Files Installed on the VPS

Runtime paths after bootstrap:

- `/root/proxy-issuer`
- `/root/proxy_issuer.py`
- `/var/lib/proxy-issuer/devices.db`
- `/etc/proxy-issuer/settings.json`
- `/etc/proxy-issuer/cloudflare.env`
- `/etc/proxy-issuer/config.base.json`
- `/etc/sing-box/config.json`

## First Use After Install

Bootstrap finishes with the system ready, but with no client devices issued yet.

Create devices manually:

```bash
/root/proxy-issuer issue mihomo-desktop my-mac
/root/proxy-issuer issue mihomo-server my-linux
/root/proxy-issuer issue shadowrocket my-phone
```

List all devices:

```bash
/root/proxy-issuer list
```

Rotate one device:

```bash
/root/proxy-issuer rotate my-mac
```

Revoke one device:

```bash
/root/proxy-issuer revoke my-mac
```

## Client Types

Supported device templates:

- `mihomo-desktop`
- `mihomo-server`
- `shadowrocket`

### `mihomo-desktop`

Includes:

- `tun`
- `fake-ip`
- `sniffer`
- `Loyalsoldier` whitelist rules

### `mihomo-server`

Includes:

- same nodes and rule strategy
- no desktop-style `tun`

### `shadowrocket`

Includes:

- native Shadowrocket config format
- same nodes
- `Johnshall`-based rule layer through Worker-hosted rule lists

## Idempotence Expectations

`bootstrap.sh` is designed to be rerunnable.

On rerun, it should:

- reuse the existing Worker when possible
- reuse the existing KV namespace when possible
- update the proxy DNS record if it drifted
- reuse existing Reality key material when already installed
- preserve the device database
- avoid creating starter devices

## Troubleshooting

### Bootstrap says the Cloudflare zone was not found

Check:

- the root domain is correct
- the domain is actually hosted in the same Cloudflare account as your tokens
- the DNS token has `Zone Read`

### Worker deployment fails

Check:

- the Workers/KV token has `Workers Scripts Write`
- the Workers/KV token has `Workers KV Storage Edit`
- if required by your account, it also has `Workers Routes Write`

### KV namespace creation fails

Check:

- the Workers/KV token is scoped to the correct Cloudflare account
- the token includes account-level KV permissions

### The proxy hostname does not point to the VPS

Check:

- the DNS token has `DNS Edit`
- there is no conflicting non-A/AAAA record for the same hostname

### Certificate issuance fails

Check:

- the DNS token is still valid
- `/etc/proxy-issuer/cloudflare.env` still contains the correct DNS token
- the hostname is still in the same Cloudflare zone

### The Worker domain responds slowly right after bootstrap

Cloudflare custom-domain propagation can take a short time. Re-run the bootstrap or retry the Worker smoke check after a short wait.

## Security Notes

- Cloudflare tokens are stored locally on the VPS in:

```text
/etc/proxy-issuer/cloudflare.env
```

- That file should remain root-readable only.
- The script does not disable password SSH by default.
- The repository template does not commit a live Reality private key or live Hysteria obfuscation secret.

## Verification Commands

Useful commands after install:

```bash
systemctl status sing-box --no-pager
/root/proxy-issuer list
curl -fsS https://sub.<your-domain>/rules/direct.txt | head
```

## Current Status of This Repository

This repository is intended to become a publishable bootstrap project. Before you publish it publicly, you should still run a clean-server end-to-end install test with your own Cloudflare zone and verify the generated first-device subscriptions on real clients.
