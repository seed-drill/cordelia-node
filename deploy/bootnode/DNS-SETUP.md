# Bootnode DNS Setup (WP12)

## Cloudflare DNS Records for seeddrill.ai

### A Records (bootnode hosts)

| Type | Name | Content | Proxy | TTL |
|------|------|---------|-------|-----|
| A | boot1.cordelia | `<fly.io boot1 IPv4>` | DNS only | 300 |
| A | boot2.cordelia | `<fly.io boot2 IPv4>` | DNS only | 300 |
| AAAA | boot1.cordelia | `<fly.io boot1 IPv6>` | DNS only | 300 |
| AAAA | boot2.cordelia | `<fly.io boot2 IPv6>` | DNS only | 300 |

Get Fly.io IPs:
```bash
fly ips list -a cordelia-boot1
fly ips list -a cordelia-boot2
```

**Important:** Set Proxy to "DNS only" (grey cloud). QUIC/UDP traffic cannot be proxied through Cloudflare.

### SRV Records (discovery)

| Type | Name | Service | Protocol | Priority | Weight | Port | Target |
|------|------|---------|----------|----------|--------|------|--------|
| SRV | seeddrill.ai | _cordelia | _udp | 10 | 0 | 9474 | boot1.cordelia.seeddrill.ai |
| SRV | seeddrill.ai | _cordelia | _udp | 20 | 0 | 9474 | boot2.cordelia.seeddrill.ai |

### Verification

```bash
# Check A records
dig boot1.cordelia.seeddrill.ai A
dig boot2.cordelia.seeddrill.ai A

# Check SRV records
dig _cordelia._udp.seeddrill.ai SRV

# Test QUIC connectivity (requires quinn or quiche)
cordelia status --check-bootnodes
```

## Deploy Sequence

1. Create Fly.io apps (if not exists):
   ```bash
   fly apps create cordelia-boot1
   fly apps create cordelia-boot2
   fly volumes create cordelia_data -a cordelia-boot1 --region lhr --size 1
   fly volumes create cordelia_data -a cordelia-boot2 --region ams --size 1
   ```

2. Deploy bootnodes:
   ```bash
   fly deploy --config deploy/bootnode/fly.boot1.toml
   fly deploy --config deploy/bootnode/fly.boot2.toml
   ```

3. Get IPs and configure DNS (see records above)

4. Allocate dedicated IPv4 (required for UDP):
   ```bash
   fly ips allocate-v4 -a cordelia-boot1
   fly ips allocate-v4 -a cordelia-boot2
   ```

5. Verify DNS resolution:
   ```bash
   dig _cordelia._udp.seeddrill.ai SRV
   ```
