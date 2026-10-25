#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
# Smoke the private tunnel topology with synthetic keys and isolated data.
# No live SuiteCRM request and no OpenAI tunnel connection is made.
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p .build
SMOKE_DIR=$(mktemp -d "$PWD/.build/smoke.XXXXXX")
export SMOKE_DIR
PROJECT="suitecrm-mcp-smoke-$$"
PROBE_CONTAINER="${PROJECT}-transport-probe"
export MCP_PROXY_NETWORK="${PROJECT}-proxy"
docker network create "$MCP_PROXY_NETWORK" >/dev/null
cleanup() {
  docker rm -f "$PROBE_CONTAINER" >/dev/null 2>&1 || true
  docker compose -p "$PROJECT" --profile oauth-edge --profile chatgpt \
    -f docker-compose.yml -f "$SMOKE_DIR/compose.override.yml" \
    --env-file "$SMOKE_DIR/env" down >/dev/null 2>&1 || true
  docker network rm "$MCP_PROXY_NETWORK" >/dev/null 2>&1 || true
  case "$SMOKE_DIR" in "$PWD"/.build/smoke.*) rm -rf -- "$SMOKE_DIR";; esac
}
trap cleanup EXIT
umask 077
SMOKE_UID="${MCP_SMOKE_UID:-$(id -u)}"
SMOKE_GID="${MCP_SMOKE_GID:-$(id -g)}"
[[ "$SMOKE_UID" =~ ^[0-9]+$ && "$SMOKE_GID" =~ ^[0-9]+$ ]]
if [[ "$SMOKE_UID" == 0 ]]; then
  echo "Refusing UID 0 for PHP-FPM smoke; set MCP_SMOKE_UID/MCP_SMOKE_GID" >&2
  exit 3
fi
mkdir -p "$SMOKE_DIR/secrets" "$SMOKE_DIR/var"
openssl rand -base64 32 > "$SMOKE_DIR/secrets/token_encryption_key"
printf 'ci-synthetic-credential-never-used\n' > "$SMOKE_DIR/secrets/suitecrm_auth_client_secret"
: > "$SMOKE_DIR/secrets/approver_public_key"
: > "$SMOKE_DIR/secrets/openai_tunnel_runtime_api_key"
cat > "$SMOKE_DIR/env" <<EOF
APP_UID=$SMOKE_UID
APP_GID=$SMOKE_GID
SUITECRM_BASE_URL=https://crm.example.com/legacy
SUITECRM_AUTH_CLIENT_ID=synthetic-crm-client
MCP_OAUTH_ISSUER=https://crm.example.com/suitecrm-mcp-auth
MCP_OAUTH_ORIGIN=https://crm.example.com
MCP_OAUTH_CLIENT_ID=synthetic-chatgpt-client
MCP_OAUTH_REDIRECT_URI=https://chatgpt.com/oauth/smoke/callback
MCP_RESOURCE_URI=https://api.openai.com/v1/mcp/tunnel_0123456789abcdef0123456789abcdef
OPENAI_TUNNEL_ID=tunnel_0123456789abcdef0123456789abcdef
MCP_ALLOWED_HOSTS=127.0.0.1,localhost,nginx,crm.example.com
EOF
if [[ "$SMOKE_UID" != "$(id -u)" ]]; then
  chown -R "$SMOKE_UID:$SMOKE_GID" "$SMOKE_DIR/secrets" "$SMOKE_DIR/var"
fi
cat > "$SMOKE_DIR/compose.override.yml" <<'EOF'
services:
  app:
    volumes:
      - ${SMOKE_DIR}/var:/app/var
secrets:
  token_encryption_key:
    file: ${SMOKE_DIR}/secrets/token_encryption_key
  approver_public_key:
    file: ${SMOKE_DIR}/secrets/approver_public_key
  suitecrm_auth_client_secret:
    file: ${SMOKE_DIR}/secrets/suitecrm_auth_client_secret
  openai_tunnel_runtime_api_key:
    file: ${SMOKE_DIR}/secrets/openai_tunnel_runtime_api_key
EOF
compose() {
  docker compose -p "$PROJECT" --profile oauth-edge --profile chatgpt \
    -f docker-compose.yml -f "$SMOKE_DIR/compose.override.yml" \
    --env-file "$SMOKE_DIR/env" "$@"
}
compose config --quiet
# Guardrail: verify Compose really uses only synthetic secrets and data volume.
compose config --format json | python3 -c '
import json, os, sys
config = json.load(sys.stdin)
root = os.environ["SMOKE_DIR"]
for name in ("app", "nginx", "tunnel"):
    assert not config["services"][name].get("ports"), "Private server published a host port"
assert not config["services"]["oauth-edge"].get("ports"), "OAuth edge published a host port"
edge_networks = config["services"]["oauth-edge"]["networks"]
assert set(edge_networks) == {"mcp_backend", "proxy_front"}
assert set(config["services"]["app"]["networks"]) == {"mcp_backend"}
assert set(config["services"]["nginx"]["networks"]) == {"mcp_backend", "mcp_transport"}
tunnel = config["services"]["tunnel"]
assert "network_mode" not in tunnel, "Tunnel must not share a service network namespace"
assert set(tunnel["networks"]) == {"mcp_transport", "tunnel_egress"}
assert tunnel["environment"]["MCP_SERVER_URL"] == "http://nginx:8080/mcp"
assert config["networks"]["mcp_transport"]["internal"] is True
assert not config["networks"]["tunnel_egress"].get("internal", False)
assert config["networks"]["proxy_front"]["name"] == os.environ["MCP_PROXY_NETWORK"]
volumes = config["services"]["app"]["volumes"]
assert any(v.get("target") == "/app/var" and v.get("source") == root+"/var" for v in volumes)
for name in ("token_encryption_key", "approver_public_key", "suitecrm_auth_client_secret"):
    secret = config["secrets"][name]
    assert secret.get("file") == root+"/secrets/"+name
'
compose up -d --build app nginx oauth-edge >/dev/null
# Run a synthetic transport-only client; never start the real tunnel with CI credentials.
nginx_id_before=$(compose ps -q nginx)
nginx_image=$(docker inspect --format '{{.Config.Image}}' "$nginx_id_before")
docker run -d --name "$PROBE_CONTAINER" --network "${PROJECT}_mcp_transport" \
  --user "${SMOKE_UID}:${SMOKE_GID}" --cap-drop ALL --security-opt no-new-privileges \
  --read-only --entrypoint /bin/sh "$nginx_image" -c 'sleep 240' >/dev/null
probe_health=$(docker exec "$PROBE_CONTAINER" wget -T 10 -t 1 -q -O - http://nginx:8080/healthz)
[[ "$probe_health" == *'"status":"alive"'* ]]
if docker exec "$PROBE_CONTAINER" nslookup app >/dev/null 2>&1; then
  echo "Transport client must not resolve the application network" >&2
  exit 1
fi
# Force an nginx replacement while the same synthetic client is running.
compose up -d --no-deps --force-recreate nginx >/dev/null
[[ "$nginx_id_before" != "$(compose ps -q nginx)" ]]
[[ "$(docker inspect --format '{{.State.Running}}' "$PROBE_CONTAINER")" == true ]]
probe_health=$(docker exec "$PROBE_CONTAINER" wget -T 10 -t 1 -q -O - http://nginx:8080/healthz)
[[ "$probe_health" == *'"status":"alive"'* ]]
health=$(compose exec -T nginx wget -T 10 -t 1 -q -O - http://127.0.0.1:8080/healthz)
[[ "$health" == *'"status":"alive"'* ]]
prmd=$(compose exec -T nginx wget -T 10 -t 1 -q -O - http://127.0.0.1:8080/.well-known/oauth-protected-resource/mcp)
[[ "$prmd" == *'"authorization_servers":["https://crm.example.com/suitecrm-mcp-auth"]'* ]]
# The private transport already advertises the canonical hosted resource;
# do not rely on rewriting loopback identifiers into an OAuth audience.
[[ "$prmd" == *'"resource":"https://api.openai.com/v1/mcp/tunnel_0123456789abcdef0123456789abcdef"'* ]]
auth_metadata=$(compose exec -T oauth-edge wget -T 10 -t 1 -q --header='Host: crm.example.com' -O - \
  http://127.0.0.1:8081/.well-known/oauth-authorization-server/suitecrm-mcp-auth)
[[ "$auth_metadata" == *'https:\/\/crm.example.com\/suitecrm-mcp-auth\/token'* ]]
[[ "$auth_metadata" == *'https:\/\/crm.example.com\/suitecrm-mcp-auth\/authorize'* ]]
mcp_response=$(compose exec -T nginx wget -T 10 -t 1 -S -O /dev/null http://127.0.0.1:8080/mcp 2>&1 || true)
[[ "$mcp_response" == *'401 Unauthorized'* ]]
for path in mcp oauth/token healthz; do
  denied=$(compose exec -T oauth-edge wget -T 10 -t 1 -S --header="Host: crm.example.com" -O /dev/null \
    "http://127.0.0.1:8081/$path" 2>&1 || true)
  [[ "$denied" == *'404 Not Found'* ]]
done
public_token_bad=$(compose exec -T oauth-edge wget -T 10 -t 1 -S \
    --header='Host: crm.example.com' \
    --post-data='grant_type=authorization_code' -O /dev/null \
    http://127.0.0.1:8081/suitecrm-mcp-auth/token 2>&1 || true)
[[ "$public_token_bad" == *'400 Bad Request'* ]]
# An additional POST probe is essential: the public OAuth regex must NOT match
# the internal /oauth/token endpoint even if the HTTP method is valid.
internal_post_public=$(compose exec -T oauth-edge wget -T 10 -t 1 -S     --header='Host: crm.example.com'     --post-data='grant_type=refresh_token' -O /dev/null     http://127.0.0.1:8081/oauth/token 2>&1 || true)
[[ "$internal_post_public" == *'404 Not Found'* ]]
# Wrong public host must be rejected before authorization starts.
forged_host=$(compose exec -T oauth-edge wget -T 10 -t 1 -S \
  --header='Host: attacker.example.test' -O /dev/null \
  http://127.0.0.1:8081/suitecrm-mcp-auth/authorize 2>&1 || true)
[[ "$forged_host" == *'421 Misdirected Request'* ]]
# The token endpoint is exact-match only; the internal generic endpoint is not public.
private_token_public=$(compose exec -T oauth-edge wget -T 10 -t 1 -S \
    --header='Host: crm.example.com' -O /dev/null \
    http://127.0.0.1:8081/oauth/token 2>&1 || true)
[[ "$private_token_public" == *'404 Not Found'* ]]
bad_token=$(compose exec -T nginx wget -T 10 -t 1 -S -O /dev/null \
    --post-data='grant_type=refresh_token' http://127.0.0.1:8080/oauth/token 2>&1 || true)
[[ "$bad_token" == *'400 Bad Request'* ]]
echo "smoke=passed; isolated_synthetic_data=true; public_mcp=false; oauth_token_post_only=true; generic_token_private=true; nginx_replacement_safe=true"
