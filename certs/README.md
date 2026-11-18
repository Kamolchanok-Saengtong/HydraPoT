# Put your TLS certificate here

Mounted read-only into the Caddy TLS layer at `/certs` (see
`docker-compose.tls.yml`). To use your organisation's own certificate instead
of Caddy's internal CA, drop the files here and point `.env` at them:

    TLS_CERT=/certs/org.crt
    TLS_KEY=/certs/org.key

Nothing real lives in git here — keep actual keys out of version control.
