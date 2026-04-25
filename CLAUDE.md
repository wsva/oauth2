# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Run

```bash
go build                    # produces ./wsva_oauth2 binary
./build.sh                  # build + prepare kustomize/ deployment dir
```

The binary is run in place — it resolves all paths relative to its own executable location (`Basepath`), so keep `config/`, `key/`, `pki/`, and `template/` directories alongside the binary.

## Configuration

The main config file is `config/auth_service_config.json`. On first start with a plaintext `DatabaseURL`, the service AES-256 encrypts it in-place and rewrites the file. Subsequent starts expect the `{AES256}...` ciphertext form.

Config fields:
- `AESKey` / `AESIV` — key material for encrypting the database URL (overridden by `AES_KEY`/`AES_IV` env vars in Kubernetes via `prod.json` substitution)
- `RSAKeyFile` / `RSAPubFile` — RSA key pair for JWT signing; use `{BasePath}` placeholder
- `HttpsCrtFile` / `HttpsKeyFile` — TLS cert/key for HTTPS listener; use `{BasePath}` placeholder
- `ListenList` — multiple listeners, each with `Enable`, `Port`, `Protocol` (`http` or `https`)

Only PostgreSQL is fully implemented in `db.go`; other driver branches return errors.

## Key Generation

```bash
# RSA (required — Auth.js needs RS256; Ed25519 is not supported by Auth.js)
openssl genrsa -out key/rsa.key 3072
openssl rsa -in key/rsa.key -pubout -out key/rsa.pub
```

## Database Schema

Three tables (PostgreSQL):

```sql
create table oauth2_user (
    user_id varchar(100) not null primary key,  -- set to email on signup
    nickname varchar(100), username varchar(100), number varchar(100),
    email varchar(100) not null, password varchar(100) not null,
    is_superuser varchar(1) not null, is_staff varchar(1) not null, is_active varchar(1) not null
);
create table oauth2_token (
    access_token varchar(1000) not null primary key,
    refresh_token varchar(1000) not null, client_id varchar(100) not null,
    user_id varchar(100) not null, ip varchar(100) not null, parent varchar(1000)
);
create table oauth2_log (
    uuid varchar(100) not null primary key,
    user_id varchar(100), ip varchar(100) not null, real_ip varchar(100), note varchar(1000)
);
```

## Architecture

Single-package Go service (`package main`) with no sub-packages:

| File | Responsibility |
|------|---------------|
| `main.go` | Router setup (gorilla/mux + negroni middleware), listener startup |
| `global.go` | Config loading, RSA key loading, global vars (`mainConfig`, `dbConfig`, `privateKey`, `publicKey`, `codeMap`, `loginAudit`) |
| `handler.go` | All HTTP handlers (`handleSignUp`, `handleSignIn`, `handleToken`, `handleAuthorize`, `handleUserInfo`, `handleRevoke`, `handleIntrospect`, `handleJwks`, `handleLogout`, `handleAccountUpdate`, `handleAccountAll`, browser page handlers) |
| `token.go` | JWT generation/verification (`RS256`), `CheckAuthorization`, cookie helpers, `ParseTokenFromRequest` |
| `db.go` | `Account` and `Token` structs with all DB operations (PostgreSQL) |
| `audit.go` | In-memory brute-force rate limiter (`LoginAudit`) — blocks after 10 combined failures per account+IP |
| `code_challenge.go` | PKCE `CodeMap` — in-memory authorization code store with S256 verification, 3-minute expiry |

## OAuth2 Flow

- **PKCE Authorization Code** (`/oauth2/authorize` → `/oauth2/token`): standard flow; `response_type=code`, `code_challenge_method=S256`
- **Direct sign-in** (`/oauth2/signin`): returns access+refresh tokens directly; used by the browser login page
- Token validation checks both JWT signature and DB presence (revocation support)
- IP binding: `CheckAuthorization` with `check_ip=true` rejects tokens used from a different IP than they were issued for
- Token deletion cascades: deleting a token also deletes its children (tokens whose `parent` column references it)

## Kubernetes Deployment

`build.sh` stamps the current timestamp into `kustomize/deployment.yaml` (replacing `BUILD_TIME`). The deployment pulls the binary from GitHub and substitutes secrets at runtime via `sed` on `prod.json`.

Kubernetes secrets required:
```bash
kubectl create secret generic secrets -n wsva \
  --from-literal=POSTGRES_PASSWORD=... \
  --from-literal=AES_KEY=... \
  --from-literal=AES_IV=...
```
