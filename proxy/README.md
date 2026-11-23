# TLS is pluggable — bring your own

HydraPoT **does not implement TLS.** The dashboard serves plain HTTP on the
Compose network (`dashboard:8050`), and a **separate, swappable layer** in front
adds HTTPS. This lets each organisation use *their* approach without changing
HydraPoT.

```
  client ──HTTPS──►  [ TLS layer ]  ──HTTP──►  dashboard:8050
                     ▲ swap this ▲             (HydraPoT, unchanged)
```

**The only contract:** terminate TLS, then `reverse_proxy` / `proxy_pass` to
`dashboard:8050`. Anything that can do that works.

---

## The reference layer (Caddy, internal CA)

Ships as `proxy/Caddyfile` + the `caddy` service in `docker-compose.yml`. Caddy issues the cert from
its **own local CA** — no external calls, nothing leaves the machine. Good for a
LAN / VPN-only deployment.

```bash
docker-compose up
# dashboard now at  https://<sensor-ip>/   (:443)
```

**One-time trust step:** because the cert is from Caddy's private CA, browsers
warn until each client trusts Caddy's root once. Export it from the running
container and install it on the org's machines (or push via MDM / Group Policy):

```bash
docker cp $(docker-compose ps -q caddy):/data/caddy/pki/authorities/local/root.crt ./hydrapot-root.crt
# then install hydrapot-root.crt as a trusted root on each client
```

---

## Plug in YOUR organisation's approach instead

Pick whichever matches how your org already does TLS — HydraPoT stays the same.

| your org already has… | how to plug in |
|---|---|
| **Internal CA (AD CS) cert** | set `dashboard.tls_cert` / `tls_key` / `tls_names` in `config.yaml` (the only place); `hp --run` or `hp --dashboard` copies them to `./certs` and `.env` for Caddy. Or use nginx below |
| **nginx standard** | run nginx instead of Caddy, `proxy_pass http://dashboard:8050;` with your cert |
| **A load balancer / ingress** (F5, AWS ALB, k8s ingress) | point it at the dashboard's `8050`; skip the TLS overlay entirely |
| **Identity-aware proxy** (Cloudflare Access, Tailscale) | front it with that; HydraPoT just serves HTTP behind it |
| **Nothing / VPN only** | skip TLS, reach the loopback `8050` over an SSH tunnel |

### nginx example (drop-in replacement for the Caddy service)

```nginx
server {
    listen 443 ssl;
    server_name honeypot.myorg.internal;
    ssl_certificate     /etc/nginx/org.crt;   # your AD CS / corporate cert
    ssl_certificate_key /etc/nginx/org.key;
    location / {
        proxy_pass http://dashboard:8050;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Edit `docker-compose.yml`, swap the `caddy` service for an `nginx` service
mounting this config + your cert. Done — same contract, your TLS.

---

## Why it's built this way

- **Separation of concerns.** Encryption is an infrastructure decision that
  differs per org; baking one choice into the app would force everyone into it.
- **Matches real deployments.** Production services sit behind a proxy / ingress
  that owns TLS — the app speaks HTTP internally. HydraPoT does the same.
- **Safer default.** The dashboard container publishes no port of its own; it is
  never on the LAN in clear. Exposure (and its encryption) is always the proxy in front.
