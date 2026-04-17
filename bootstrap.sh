#!/usr/bin/env bash
set -euo pipefail

IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATES_DIR="${REPO_ROOT}/templates"
DEVICE_ISSUER_DIR="${REPO_ROOT}/device-issuer"
WORKER_DIR="${REPO_ROOT}/subscription-worker"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

readonly CF_API_BASE="https://api.cloudflare.com/client/v4"
readonly DEFAULT_REALITY_SERVER_NAME="www.microsoft.com"

log() {
  printf '[bootstrap] %s\n' "$*"
}

die() {
  printf '[bootstrap] ERROR: %s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "${EUID}" -eq 0 ]] || die "run as root"
}

require_ubuntu() {
  [[ -f /etc/os-release ]] || die "unsupported system"
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" ]] || die "this bootstrap only supports Ubuntu"
}

prompt_value() {
  local var_name="$1"
  local prompt_label="$2"
  local secret="${3:-false}"
  local default_value="${4:-}"
  local current_value="${!var_name:-}"
  local answer=""

  if [[ -n "${current_value}" ]]; then
    return
  fi

  if [[ ! -t 0 ]]; then
    if [[ -n "${default_value}" ]]; then
      printf -v "${var_name}" '%s' "${default_value}"
      return
    fi
    die "missing required input for ${var_name} in non-interactive mode"
  fi

  while [[ -z "${answer}" ]]; do
    if [[ "${secret}" == "true" ]]; then
      read -r -s -p "${prompt_label}: " answer
      printf '\n'
    elif [[ -n "${default_value}" ]]; then
      read -r -p "${prompt_label} [${default_value}]: " answer
      answer="${answer:-${default_value}}"
    else
      read -r -p "${prompt_label}: " answer
    fi
  done

  printf -v "${var_name}" '%s' "${answer}"
}

prompt_optional_value() {
  local var_name="$1"
  local prompt_label="$2"
  local current_value="${!var_name:-}"
  local answer=""

  if [[ -n "${current_value}" ]]; then
    return
  fi

  if [[ ! -t 0 ]]; then
    printf -v "${var_name}" '%s' ""
    return
  fi

  read -r -p "${prompt_label}: " answer
  printf -v "${var_name}" '%s' "${answer}"
}

json_get() {
  local file="$1"
  local query="$2"
  [[ -f "${file}" ]] || return 0
  jq -r "${query} // empty" "${file}"
}

ensure_base_packages() {
  log "installing base packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y \
    ca-certificates \
    curl \
    gettext-base \
    git \
    gnupg \
    jq \
    python3 \
    sqlite3 \
    ufw \
    unzip
}

ensure_node_and_wrangler() {
  local need_node="true"
  if command -v node >/dev/null 2>&1; then
    local major
    major="$(node -p 'process.versions.node.split(".")[0]')"
    if [[ "${major}" -ge 20 ]]; then
      need_node="false"
    fi
  fi

  if [[ "${need_node}" == "true" ]]; then
    log "installing Node.js LTS"
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt-get install -y nodejs
  else
    log "Node.js already suitable"
  fi

  if command -v wrangler >/dev/null 2>&1; then
    log "wrangler already installed"
  else
    log "installing wrangler"
    npm install -g wrangler
  fi
}

ensure_sing_box() {
  if command -v sing-box >/dev/null 2>&1; then
    log "sing-box already installed"
    systemctl enable --now sing-box >/dev/null 2>&1 || true
    return
  fi

  local arch
  case "$(dpkg --print-architecture)" in
    amd64) arch="amd64" ;;
    arm64) arch="arm64" ;;
    *) die "unsupported architecture for sing-box" ;;
  esac

  log "installing sing-box"
  local asset_url package_path
  asset_url="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest \
    | jq -r --arg arch "${arch}" '.assets[]?.browser_download_url | select(test("linux_" + $arch + "\\.deb$"))' \
    | head -n 1)"
  [[ -n "${asset_url}" ]] || die "unable to resolve sing-box package URL"

  package_path="${TMP_DIR}/sing-box.deb"
  curl -fsSL "${asset_url}" -o "${package_path}"
  apt-get install -y "${package_path}"
  systemctl enable --now sing-box
}

detect_public_ipv4() {
  curl -4 -fsS https://api.ipify.org || true
}

detect_public_ipv6() {
  curl -6 -fsS https://api64.ipify.org || true
}

cf_api() {
  local method="$1"
  local token="$2"
  local path="$3"
  local body="${4:-}"
  if [[ -n "${body}" ]]; then
    curl -fsS -X "${method}" "${CF_API_BASE}${path}" \
      -H "Authorization: Bearer ${token}" \
      -H "Content-Type: application/json" \
      --data "${body}"
  else
    curl -fsS -X "${method}" "${CF_API_BASE}${path}" \
      -H "Authorization: Bearer ${token}" \
      -H "Content-Type: application/json"
  fi
}

cf_expect_success() {
  local payload="$1"
  local success
  success="$(jq -r '.success' <<<"${payload}")"
  [[ "${success}" == "true" ]] || die "Cloudflare API failed: $(jq -c '.errors' <<<"${payload}")"
}

collect_inputs() {
  log "collecting bootstrap inputs"
  prompt_value ROOT_DOMAIN "Cloudflare root domain"
  prompt_value PROXY_SUBDOMAIN "Proxy subdomain label" false "proxy"
  prompt_value SUBSCRIPTION_SUBDOMAIN "Subscription subdomain label" false "sub"
  prompt_value CLOUDFLARE_DNS_API_TOKEN "Cloudflare DNS token" true
  prompt_value CLOUDFLARE_WORKERS_API_TOKEN "Cloudflare Workers/KV token" true
  prompt_optional_value ACME_EMAIL "ACME contact email (optional)"

  PROXY_HOST="${PROXY_SUBDOMAIN}.${ROOT_DOMAIN}"
  SUBSCRIPTION_HOST="${SUBSCRIPTION_SUBDOMAIN}.${ROOT_DOMAIN}"
  PUBLIC_IPV4="$(detect_public_ipv4)"
  PUBLIC_IPV6="$(detect_public_ipv6)"
  [[ -n "${PUBLIC_IPV4}" ]] || die "unable to detect public IPv4"
}

ensure_cloudflare_context() {
  log "discovering Cloudflare zone and account"
  local zone_payload
  zone_payload="$(cf_api GET "${CLOUDFLARE_DNS_API_TOKEN}" "/zones?name=${ROOT_DOMAIN}&status=active&per_page=1")"
  cf_expect_success "${zone_payload}"

  CLOUDFLARE_ZONE_ID="$(jq -r '.result[0].id // empty' <<<"${zone_payload}")"
  CLOUDFLARE_ACCOUNT_ID="$(jq -r '.result[0].account.id // empty' <<<"${zone_payload}")"
  [[ -n "${CLOUDFLARE_ZONE_ID}" ]] || die "Cloudflare zone not found: ${ROOT_DOMAIN}"
  [[ -n "${CLOUDFLARE_ACCOUNT_ID}" ]] || die "unable to determine Cloudflare account id"
}

ensure_kv_namespace() {
  local namespace_title="proxy-subscriptions-${ROOT_DOMAIN}"
  log "ensuring KV namespace ${namespace_title}"

  local list_payload
  list_payload="$(cf_api GET "${CLOUDFLARE_WORKERS_API_TOKEN}" "/accounts/${CLOUDFLARE_ACCOUNT_ID}/storage/kv/namespaces?per_page=100")"
  cf_expect_success "${list_payload}"

  CLOUDFLARE_KV_NAMESPACE_ID="$(jq -r --arg title "${namespace_title}" '.result[] | select(.title == $title) | .id' <<<"${list_payload}" | head -n 1)"
  if [[ -n "${CLOUDFLARE_KV_NAMESPACE_ID}" ]]; then
    log "KV namespace already exists"
    return
  fi

  local create_payload
  create_payload="$(cf_api POST "${CLOUDFLARE_WORKERS_API_TOKEN}" "/accounts/${CLOUDFLARE_ACCOUNT_ID}/storage/kv/namespaces" "{\"title\":\"${namespace_title}\"}")"
  cf_expect_success "${create_payload}"
  CLOUDFLARE_KV_NAMESPACE_ID="$(jq -r '.result.id // empty' <<<"${create_payload}")"
  [[ -n "${CLOUDFLARE_KV_NAMESPACE_ID}" ]] || die "unable to create KV namespace"
}

ensure_dns_record() {
  local type="$1"
  local name="$2"
  local content="$3"

  [[ -n "${content}" ]] || return 0

  local record_payload
  record_payload="$(cf_api GET "${CLOUDFLARE_DNS_API_TOKEN}" "/zones/${CLOUDFLARE_ZONE_ID}/dns_records?type=${type}&name=${name}")"
  cf_expect_success "${record_payload}"

  local record_id
  record_id="$(jq -r '.result[0].id // empty' <<<"${record_payload}")"
  local desired_body
  desired_body="$(jq -cn --arg type "${type}" --arg name "${name}" --arg content "${content}" '{type:$type,name:$name,content:$content,ttl:1,proxied:false}')"

  if [[ -n "${record_id}" ]]; then
    local current_content current_proxied
    current_content="$(jq -r '.result[0].content // empty' <<<"${record_payload}")"
    current_proxied="$(jq -r '.result[0].proxied // false' <<<"${record_payload}")"
    if [[ "${current_content}" == "${content}" && "${current_proxied}" == "false" ]]; then
      log "DNS ${type} ${name} already up to date"
      return
    fi

    log "updating DNS ${type} ${name}"
    local update_payload
    update_payload="$(cf_api PUT "${CLOUDFLARE_DNS_API_TOKEN}" "/zones/${CLOUDFLARE_ZONE_ID}/dns_records/${record_id}" "${desired_body}")"
    cf_expect_success "${update_payload}"
    return
  fi

  log "creating DNS ${type} ${name}"
  local create_payload
  create_payload="$(cf_api POST "${CLOUDFLARE_DNS_API_TOKEN}" "/zones/${CLOUDFLARE_ZONE_ID}/dns_records" "${desired_body}")"
  cf_expect_success "${create_payload}"
}

ensure_dns_records() {
  log "ensuring proxy DNS records"
  ensure_dns_record "A" "${PROXY_HOST}" "${PUBLIC_IPV4}"
  if [[ -n "${PUBLIC_IPV6}" ]]; then
    ensure_dns_record "AAAA" "${PROXY_HOST}" "${PUBLIC_IPV6}"
  else
    log "no public IPv6 detected; skipping AAAA record management"
  fi
}

generate_reality_materials_if_needed() {
  local existing_settings="/etc/proxy-issuer/settings.json"
  local existing_base="/etc/sing-box/config.base.json"

  REALITY_SERVER_NAME="$(json_get "${existing_settings}" '.reality_server_name')"
  REALITY_SERVER_NAME="${REALITY_SERVER_NAME:-${DEFAULT_REALITY_SERVER_NAME}}"

  REALITY_PUBLIC_KEY="$(json_get "${existing_settings}" '.reality_public_key')"
  REALITY_SHORT_ID="$(json_get "${existing_settings}" '.reality_short_id')"
  REALITY_PRIVATE_KEY="$(json_get "${existing_base}" '.inbounds[] | select(.type == "vless") | .tls.reality.private_key')"
  HY2_OBFS_PASSWORD="$(json_get "${existing_base}" '.inbounds[] | select(.type == "hysteria2") | .obfs.password')"

  if [[ -z "${REALITY_PRIVATE_KEY}" || -z "${REALITY_PUBLIC_KEY}" ]]; then
    log "generating Reality key pair"
    local keypair_output
    keypair_output="$(sing-box generate reality-keypair)"
    REALITY_PRIVATE_KEY="$(awk '/^PrivateKey:/ {print $2}' <<<"${keypair_output}")"
    REALITY_PUBLIC_KEY="$(awk '/^PublicKey:/ {print $2}' <<<"${keypair_output}")"
  fi

  if [[ -z "${REALITY_SHORT_ID}" ]]; then
    REALITY_SHORT_ID="$(sing-box generate rand 8 --hex)"
  fi

  if [[ -z "${HY2_OBFS_PASSWORD}" ]]; then
    HY2_OBFS_PASSWORD="$(sing-box generate rand 24 --hex)"
  fi
}

write_if_changed() {
  local source_file="$1"
  local destination="$2"
  local mode="$3"
  mkdir -p "$(dirname "${destination}")"
  if [[ -f "${destination}" ]] && cmp -s "${source_file}" "${destination}"; then
    return 0
  fi
  install -m "${mode}" "${source_file}" "${destination}"
}

render_template_to() {
  local template_file="$1"
  local destination="$2"
  local mode="$3"
  local rendered="${TMP_DIR}/$(basename "${destination}").rendered"
  envsubst < "${template_file}" > "${rendered}"
  write_if_changed "${rendered}" "${destination}" "${mode}"
}

render_base_config() {
  local output_file="$1"
  python3 - "${TEMPLATES_DIR}/config.base.json" > "${output_file}" <<'PY'
import json
import os
import sys
from pathlib import Path

template_path = Path(sys.argv[1])
config = json.loads(template_path.read_text(encoding="utf-8"))

for inbound in config.get("inbounds", []):
    if inbound.get("type") == "vless":
        inbound["tls"]["server_name"] = os.environ["REALITY_SERVER_NAME"]
        inbound["tls"]["reality"]["handshake"]["server"] = os.environ["REALITY_SERVER_NAME"]
        inbound["tls"]["reality"]["private_key"] = os.environ["REALITY_PRIVATE_KEY"]
        inbound["tls"]["reality"]["short_id"] = [os.environ["REALITY_SHORT_ID"]]
    elif inbound.get("type") == "hysteria2":
        inbound["obfs"]["password"] = os.environ["HY2_OBFS_PASSWORD"]
        inbound["tls"]["server_name"] = os.environ["PROXY_HOST"]
        inbound["tls"]["acme"]["domain"] = [os.environ["PROXY_HOST"]]
        inbound["tls"]["acme"]["default_server_name"] = os.environ["PROXY_HOST"]
        inbound["tls"]["acme"]["dns01_challenge"]["api_token"] = os.environ["CLOUDFLARE_DNS_API_TOKEN"]
        if os.environ.get("ACME_EMAIL"):
            inbound["tls"]["acme"]["email"] = os.environ["ACME_EMAIL"]

json.dump(config, sys.stdout, indent=2)
sys.stdout.write("\n")
PY
}

install_runtime_files() {
  log "installing runtime files"
  install -d -m 700 /etc/proxy-issuer /var/lib/proxy-issuer /var/lib/proxy-issuer/worker-sync

  export PROXY_HOST SUBSCRIPTION_HOST REALITY_SERVER_NAME REALITY_PUBLIC_KEY REALITY_PRIVATE_KEY REALITY_SHORT_ID HY2_OBFS_PASSWORD ACME_EMAIL
  export CLOUDFLARE_DNS_API_TOKEN CLOUDFLARE_WORKERS_API_TOKEN CLOUDFLARE_ACCOUNT_ID CLOUDFLARE_ZONE_ID CLOUDFLARE_KV_NAMESPACE_ID

  render_template_to "${TEMPLATES_DIR}/settings.json.tpl" "/etc/proxy-issuer/settings.json" 600
  render_template_to "${TEMPLATES_DIR}/cloudflare.env.tpl" "/etc/proxy-issuer/cloudflare.env" 600

  local rendered_base="${TMP_DIR}/config.base.json"
  render_base_config "${rendered_base}"
  write_if_changed "${rendered_base}" "/etc/sing-box/config.base.json" 600

  install -m 700 "${DEVICE_ISSUER_DIR}/proxy_issuer.py" /root/proxy_issuer.py
  install -m 755 "${DEVICE_ISSUER_DIR}/proxy-issuer" /root/proxy-issuer
}

ensure_worker_deployment() {
  log "deploying Worker"
  export WORKER_NAME="${ROOT_DOMAIN//./-}-proxy-subscription"
  export KV_NAMESPACE_ID="${CLOUDFLARE_KV_NAMESPACE_ID}"
  export SUBSCRIPTION_HOST

  render_template_to "${TEMPLATES_DIR}/wrangler.toml.tpl" "${WORKER_DIR}/wrangler.toml" 600

  (
    cd "${WORKER_DIR}"
    CLOUDFLARE_API_TOKEN="${CLOUDFLARE_WORKERS_API_TOKEN}" \
    CLOUDFLARE_ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID}" \
    wrangler deploy
  )
}

initialize_runtime_state() {
  log "rendering initial sing-box runtime state"
  /root/proxy-issuer render >/dev/null
}

configure_ssh_and_ufw() {
  log "configuring SSH and UFW"
  local sshd_snippet="${TMP_DIR}/90-proxy-bootstrap.conf"
  cat > "${sshd_snippet}" <<'EOF'
X11Forwarding no
AllowTcpForwarding no
MaxAuthTries 3
EOF
  write_if_changed "${sshd_snippet}" "/etc/ssh/sshd_config.d/90-proxy-bootstrap.conf" 644
  sshd -t
  systemctl reload ssh

  ufw --force enable
  if ! ufw status | grep -q '^22/tcp .*LIMIT'; then
    ufw limit 22/tcp
  fi
  if ! ufw status | grep -q '^443/tcp .*ALLOW'; then
    ufw allow 443/tcp
  fi
  if ! ufw status | grep -q '^443/udp .*ALLOW'; then
    ufw allow 443/udp
  fi
}

retry_curl() {
  local url="$1"
  local attempts="${2:-10}"
  local sleep_seconds="${3:-3}"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if curl -fsS "${url}" >/dev/null; then
      return 0
    fi
    sleep "${sleep_seconds}"
  done
  return 1
}

run_smoke_tests() {
  log "running smoke tests"
  systemctl is-active sing-box >/dev/null
  retry_curl "https://${SUBSCRIPTION_HOST}/rules/direct.txt"
  /root/proxy-issuer list >/dev/null
}

main() {
  require_root
  require_ubuntu
  collect_inputs
  ensure_base_packages
  ensure_node_and_wrangler
  ensure_sing_box
  ensure_cloudflare_context
  ensure_kv_namespace
  ensure_dns_records
  generate_reality_materials_if_needed
  install_runtime_files
  ensure_worker_deployment
  initialize_runtime_state
  configure_ssh_and_ufw
  run_smoke_tests
  log "bootstrap complete"
  log "next step: /root/proxy-issuer issue mihomo-desktop my-mac"
}

main "$@"
