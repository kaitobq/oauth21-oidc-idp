# OAuth 2.1 / OIDC Identity Provider

OAuth 2.1 と OpenID Connect に準拠した Identity Provider。

## Architecture

- **Frontend**: [Vinext](https://github.com/cloudflare/vinext) (Vite + Next.js API surface on Cloudflare Workers)
- **Backend**: Go + [Connect RPC](https://connectrpc.com/)
- **Schema**: Protocol Buffers (single source of truth for types)
- **Build**: [Buf](https://buf.build/) for proto management and code generation

## Directory Structure

```
proto/          # Protocol Buffers definitions (single source of truth)
backend/        # Go backend (Connect RPC server)
frontend/       # Vinext frontend (TypeScript)
scripts/        # Build and generation scripts
```

## Prerequisites

- Go 1.23+
- Node.js 22+ / pnpm 9+
- [Buf CLI](https://buf.build/docs/installation)
- [Protoc](https://grpc.io/docs/protoc-installation/)

## Getting Started

```bash
# Install dependencies
make setup

# Generate code from proto definitions
make gen

# Run backend
make run-backend

# Run frontend
make run-frontend
```

## Development

```bash
# Run all checks
make check

# Run tests
make test

# Lint proto files
make lint-proto
```
