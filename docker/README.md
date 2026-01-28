# Bitcoin Ghost Docker Deployment

This directory contains Docker configuration for deploying Bitcoin Ghost.

## Quick Start

```bash
# Copy environment file and customize
cp .env.example .env
nano .env

# Start basic stack (bitcoind + ghost-pool)
docker-compose up -d

# Start with SV1 translator
docker-compose --profile sv1 up -d

# Start with L2 (Ghost Pay)
docker-compose --profile l2 up -d

# Start with monitoring (Prometheus + Grafana)
docker-compose --profile monitoring up -d

# Start full stack
docker-compose --profile sv1 --profile l2 --profile monitoring up -d
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Docker Network                          │
│                     (172.28.0.0/16)                        │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  bitcoind   │  │  ghost-pool │  │    prometheus       │ │
│  │  :8332 RPC  │──│  :8080 API  │──│    :9090           │ │
│  │  :28332 ZMQ │  │  :34255 SV2 │  └─────────┬───────────┘ │
│  └─────────────┘  │  :8555-8562 │            │             │
│                   └──────┬──────┘            │             │
│                          │                    │             │
│  ┌─────────────┐  ┌──────┴──────┐  ┌─────────┴───────────┐ │
│  │ translator  │  │  ghost-pay  │  │      grafana        │ │
│  │ :3333 SV1   │  │  :8081 L2   │  │      :3000          │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Profiles

| Profile | Services | Use Case |
|---------|----------|----------|
| (default) | bitcoind, ghost-pool | Minimal setup |
| sv1 | + translator | Support SV1 miners |
| l2 | + ghost-pay | Enable L2 payments |
| wraith | + ghost-coordinator | Enable Wraith mixing |
| monitoring | + prometheus, grafana | Metrics & dashboards |

## Configuration Files

| File | Purpose |
|------|---------|
| `config/bitcoin.conf` | Bitcoin Core configuration |
| `config/ghost-pool.toml` | Pool node configuration |
| `config/ghost-pay.toml` | L2 node configuration |
| `config/ghost-coordinator.toml` | Wraith coordinator configuration |
| `config/prometheus.yml` | Prometheus scrape configuration |

## Environment Variables

See `.env.example` for all available variables.

## Volumes

| Volume | Purpose |
|--------|---------|
| bitcoin-data | Bitcoin blockchain data |
| ghost-data | Pool database and state |
| ghostpay-data | L2 database |
| prometheus-data | Metrics storage |
| grafana-data | Dashboard storage |

## Ports

| Port | Service | Protocol |
|------|---------|----------|
| 3000 | Grafana | HTTP |
| 3333 | Translator | Stratum V1 |
| 8080 | Ghost Pool API | HTTP |
| 8081 | Ghost Pay API | HTTP |
| 8333 | Coordinator API | HTTP |
| 9090 | Prometheus | HTTP |
| 34255 | Ghost Pool | Stratum V2 |
| 8555-8562 | Ghost Pool P2P | TCP |

## Building

```bash
# Build all images
docker-compose build

# Build specific service
docker-compose build ghost-pool
```

## Logs

```bash
# View all logs
docker-compose logs -f

# View specific service
docker-compose logs -f ghost-pool
```

## Maintenance

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (WARNING: deletes data)
docker-compose down -v

# Update images
docker-compose pull
docker-compose up -d
```

## Production Notes

1. **Change default passwords** in `.env`
2. **Configure firewall** to only expose necessary ports
3. **Use external volumes** for persistent data
4. **Enable monitoring** profile for production
5. **Configure backups** for volumes
