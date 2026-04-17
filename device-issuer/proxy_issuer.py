import argparse
import copy
import json
import secrets
import sqlite3
import subprocess
import tempfile
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from textwrap import dedent


DEVICE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL UNIQUE,
    device_name TEXT NOT NULL UNIQUE,
    client_type TEXT NOT NULL,
    status TEXT NOT NULL,
    subscription_token TEXT NOT NULL UNIQUE,
    vless_uuid TEXT NOT NULL,
    hy2_password TEXT NOT NULL,
    hy2_obfs_password TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    revoked_at TEXT,
    last_issued_at TEXT NOT NULL,
    note TEXT
)
"""


def repository_root():
    return Path(__file__).resolve().parent.parent


def repository_base_config_path():
    return repository_root() / "templates" / "config.base.json"


def init_db(db_path):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(path)
    try:
        conn.execute(DEVICE_TABLE_SQL)
        conn.commit()
    finally:
        conn.close()


def load_settings(path):
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_base_config(path):
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


RULE_PROVIDER_BEHAVIORS = {
    "reject": "domain",
    "icloud": "domain",
    "apple": "domain",
    "google": "domain",
    "proxy": "domain",
    "direct": "domain",
    "private": "domain",
    "telegramcidr": "ipcidr",
    "cncidr": "ipcidr",
    "lancidr": "ipcidr",
    "applications": "classical",
}

RULE_PROVIDER_ORDER = [
    "reject",
    "icloud",
    "apple",
    "google",
    "proxy",
    "direct",
    "private",
    "telegramcidr",
    "cncidr",
    "lancidr",
    "applications",
]

MIHOMO_RULES = [
    "RULE-SET,applications,DIRECT",
    "DOMAIN,clash.razord.top,DIRECT",
    "DOMAIN,yacd.haishan.me,DIRECT",
    "RULE-SET,private,DIRECT",
    "RULE-SET,reject,REJECT",
    "RULE-SET,icloud,DIRECT",
    "RULE-SET,apple,DIRECT",
    "RULE-SET,google,PROXY",
    "RULE-SET,proxy,PROXY",
    "RULE-SET,direct,DIRECT",
    "RULE-SET,lancidr,DIRECT",
    "RULE-SET,cncidr,DIRECT",
    "RULE-SET,telegramcidr,PROXY",
    "GEOIP,LAN,DIRECT",
    "GEOIP,CN,DIRECT",
    "MATCH,PROXY",
]

SHADOWROCKET_REMOTE_RULES = [
    ("reject", "REJECT"),
    ("private", "DIRECT"),
    ("icloud", "DIRECT"),
    ("apple", "DIRECT"),
    ("google", "PROXY"),
    ("proxy", "PROXY"),
    ("direct", "DIRECT"),
    ("lancidr", "DIRECT"),
    ("cncidr", "DIRECT"),
    ("telegramcidr", "PROXY"),
]

SHADOWROCKET_PRIVATE_RULES = [
    "DOMAIN-SUFFIX,cn,DIRECT",
    "GEOIP,CN,DIRECT",
    "IP-CIDR,192.168.0.0/16,DIRECT",
    "IP-CIDR,10.0.0.0/8,DIRECT",
    "IP-CIDR,172.16.0.0/12,DIRECT",
    "IP-CIDR,127.0.0.0/8,DIRECT",
    "IP-CIDR,fe80::/10,DIRECT",
    "IP-CIDR,fc00::/7,DIRECT",
    "IP-CIDR,::1/128,DIRECT",
]

def _yaml_list(items, indent):
    prefix = " " * indent
    return "\n".join(f"{prefix}- {item}" for item in items)


def _render_mihomo_proxies(device, settings):
    hy2_alpn = _yaml_list(settings["hysteria2_alpn"], 6)
    return dedent(
        f"""\
        proxies:
          - name: SG VLESS Reality
            type: vless
            server: {settings["proxy_server"]}
            port: 443
            udp: true
            uuid: {device["vless_uuid"]}
            flow: xtls-rprx-vision
            packet-encoding: xudp
            tls: true
            servername: {settings["reality_server_name"]}
            alpn:
              - h2
              - http/1.1
            client-fingerprint: chrome
            skip-cert-verify: false
            reality-opts:
              public-key: {settings["reality_public_key"]}
              short-id: {settings["reality_short_id"]}
            network: tcp
          - name: SG Hysteria2
            type: hysteria2
            server: {settings["proxy_server"]}
            port: 443
            password: {device["hy2_password"]}
            up: "30 Mbps"
            down: "200 Mbps"
            obfs: salamander
            obfs-password: {device["hy2_obfs_password"]}
            sni: {settings["hysteria2_sni"]}
            alpn:
        {hy2_alpn}
            skip-cert-verify: false
        """
    )


def _render_mihomo_rule_providers(settings):
    base_url = settings["mihomo_rule_base_url"]
    lines = ["rule-providers:"]
    for name in RULE_PROVIDER_ORDER:
        behavior = RULE_PROVIDER_BEHAVIORS[name]
        lines.extend(
            [
                f"  {name}:",
                "    type: http",
                f"    behavior: {behavior}",
                f'    url: "{base_url}/{name}.txt"',
                f'    path: "./ruleset/{name}.txt"',
                "    interval: 86400",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def _render_mihomo_proxy_groups():
    return dedent(
        """\
        proxy-groups:
          - name: AUTO
            type: url-test
            proxies:
              - SG VLESS Reality
              - SG Hysteria2
            url: https://cp.cloudflare.com/generate_204
            interval: 300
            tolerance: 50

          - name: PROXY
            type: select
            proxies:
              - AUTO
              - SG VLESS Reality
              - SG Hysteria2
              - DIRECT
        """
    )


def _render_mihomo_rules():
    rule_lines = "\n".join(f"  - {rule}" for rule in MIHOMO_RULES)
    return f"rules:\n{rule_lines}\n"


def _render_mihomo_desktop_preamble():
    return dedent(
        """\
        mixed-port: 7890
        mode: rule
        allow-lan: false
        ipv6: true
        log-level: info
        unified-delay: true
        tcp-concurrent: true
        find-process-mode: strict
        global-client-fingerprint: chrome

        profile:
          store-selected: true
          store-fake-ip: true

        dns:
          enable: true
          ipv6: true
          listen: 127.0.0.1:1053
          enhanced-mode: fake-ip
          fake-ip-range: 198.18.0.1/16
          respect-rules: true
          use-hosts: true
          default-nameserver:
            - 223.5.5.5
            - 119.29.29.29
          nameserver:
            - https://1.1.1.1/dns-query
            - https://8.8.8.8/dns-query
          proxy-server-nameserver:
            - 223.5.5.5
            - 119.29.29.29
          fallback:
            - https://1.0.0.1/dns-query
            - tls://8.8.4.4:853
          nameserver-policy:
            "rule-set:direct":
              - 223.5.5.5
              - 119.29.29.29
            "rule-set:private":
              - 223.5.5.5
              - 119.29.29.29
          fake-ip-filter:
            - "*.lan"
            - "*.local"
            - "localhost.ptlogin2.qq.com"
            - "+.msftconnecttest.com"
            - "+.msftncsi.com"
            - "time.*.com"
            - "time.*.gov"
            - "time.*.edu.cn"

        sniffer:
          enable: true
          sniff:
            TLS:
              ports: [443, 8443]
            HTTP:
              ports: [80, 8080-8880]
              override-destination: true
            QUIC:
              ports: [443, 8443]
          force-dns-mapping: true
          parse-pure-ip: true

        tun:
          enable: true
          stack: mixed
          dns-hijack:
            - any:53
          auto-route: true
          auto-detect-interface: true
        """
    )


def _render_mihomo_server_preamble():
    return dedent(
        """\
        mixed-port: 7890
        mode: rule
        allow-lan: false
        ipv6: true
        log-level: info
        unified-delay: true
        tcp-concurrent: true
        find-process-mode: strict
        global-client-fingerprint: chrome

        profile:
          store-selected: true

        dns:
          enable: true
          ipv6: true
          respect-rules: true
          use-hosts: true
          enhanced-mode: redir-host
          nameserver:
            - 223.5.5.5
            - 119.29.29.29
            - https://1.1.1.1/dns-query
            - https://8.8.8.8/dns-query
          proxy-server-nameserver:
            - 223.5.5.5
            - 119.29.29.29
        """
    )


def render_mihomo_desktop(device, settings):
    sections = [
        _render_mihomo_desktop_preamble().rstrip(),
        _render_mihomo_proxies(device, settings).rstrip(),
        _render_mihomo_proxy_groups().rstrip(),
        _render_mihomo_rule_providers(settings).rstrip(),
        _render_mihomo_rules().rstrip(),
    ]
    return "\n\n".join(sections) + "\n"


def render_mihomo_server(device, settings):
    sections = [
        _render_mihomo_server_preamble().rstrip(),
        _render_mihomo_proxies(device, settings).rstrip(),
        _render_mihomo_proxy_groups().rstrip(),
        _render_mihomo_rule_providers(settings).rstrip(),
        _render_mihomo_rules().rstrip(),
    ]
    return "\n\n".join(sections) + "\n"


def render_shadowrocket(device, settings):
    base_url = settings["shadowrocket_rule_base_url"]
    remote_rules = "\n".join(
        f"RULE-SET,{base_url}/{name}.list,{policy}"
        for name, policy in SHADOWROCKET_REMOTE_RULES
    )
    private_rules = "\n".join(SHADOWROCKET_PRIVATE_RULES)
    sections = [
        dedent(
            """\
            [General]
            ipv6 = true
            bypass-system = true
            private-ip-answer = true
            dns-direct-fallback-proxy = true
            dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query, https://1.1.1.1/dns-query, 223.5.5.5, 119.29.29.29
            fallback-dns-server = system
            skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.0/8,localhost,*.local
            """
        ).rstrip(),
        dedent(
            f"""\
            [Proxy]
            SG VLESS Reality = vless, {settings["proxy_server"]}, 443, username={device["vless_uuid"]}, tls=true, sni={settings["reality_server_name"]}, flow=xtls-rprx-vision, udp-relay=true, client-fingerprint=chrome, reality-public-key={settings["reality_public_key"]}, reality-short-id={settings["reality_short_id"]}
            SG Hysteria2 = hysteria2, {settings["proxy_server"]}, 443, password={device["hy2_password"]}, sni={settings["hysteria2_sni"]}, obfs=salamander, obfs-password={device["hy2_obfs_password"]}, alpn={",".join(settings["hysteria2_alpn"])}, udp-relay=true
            """
        ).rstrip(),
        dedent(
            """\
            [Proxy Group]
            AUTO = url-test, SG VLESS Reality, SG Hysteria2, url=http://www.gstatic.com/generate_204, interval=300
            PROXY = select, AUTO, SG VLESS Reality, SG Hysteria2, DIRECT
            """
        ).rstrip(),
        "\n".join(["[Rule]", remote_rules, private_rules, "FINAL,PROXY"]).rstrip(),
    ]
    return "\n\n".join(sections) + "\n"


def render_subscription(device, settings):
    client_type = device["client_type"]
    if client_type == "mihomo-desktop":
        return render_mihomo_desktop(device, settings), "text/yaml; charset=utf-8"
    if client_type == "mihomo-server":
        return render_mihomo_server(device, settings), "text/yaml; charset=utf-8"
    if client_type == "shadowrocket":
        return render_shadowrocket(device, settings), "text/plain; charset=utf-8"
    raise ValueError(f"Unsupported client_type: {client_type}")


def build_sing_box_config(base_config, devices, settings, dns_api_token):
    config = copy.deepcopy(base_config)
    active_devices = [device for device in devices if device.get("status") == "active"]

    for inbound in config.get("inbounds", []):
        if inbound.get("type") == "vless":
            inbound["tag"] = "vless-reality-in"
            inbound["users"] = [
                {
                    "name": device["device_name"],
                    "uuid": device["vless_uuid"],
                    "flow": "xtls-rprx-vision",
                }
                for device in active_devices
            ]
            inbound["tls"]["server_name"] = settings["reality_server_name"]
            inbound["tls"]["reality"]["handshake"]["server"] = settings[
                "reality_server_name"
            ]
            inbound["tls"]["reality"]["short_id"] = [settings["reality_short_id"]]
        elif inbound.get("type") == "hysteria2":
            inbound["tag"] = "hy2-in"
            inbound["users"] = [
                {"name": device["device_name"], "password": device["hy2_password"]}
                for device in active_devices
            ]
            inbound["tls"]["server_name"] = settings["hysteria2_sni"]
            inbound["tls"]["alpn"] = list(settings["hysteria2_alpn"])
            inbound["tls"]["acme"]["domain"] = [settings["hysteria2_sni"]]
            inbound["tls"]["acme"]["default_server_name"] = settings["hysteria2_sni"]
            inbound["tls"]["acme"]["dns01_challenge"]["api_token"] = dns_api_token

    return config


def run_checked(cmd):
    subprocess.run(cmd, check=True, text=True)


def validate_sing_box(config_path):
    run_checked(["sing-box", "check", "-c", str(Path(config_path))])


def reload_sing_box():
    run_checked(["systemctl", "reload", "sing-box"])


SUPPORTED_CLIENT_TYPES = ("mihomo-desktop", "mihomo-server", "shadowrocket")


@dataclass(frozen=True)
class RuntimePaths:
    db_path: Path = Path("/var/lib/proxy-issuer/devices.db")
    settings_path: Path = Path("/etc/proxy-issuer/settings.json")
    base_config_path: Path = Path("/etc/sing-box/config.base.json")
    live_config_path: Path = Path("/etc/sing-box/config.json")
    cloudflare_env_path: Path = Path("/etc/proxy-issuer/cloudflare.env")


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def generate_device_id():
    return f"dev_{datetime.now(timezone.utc).strftime('%Y%m%d')}_{secrets.token_hex(4)}"


def generate_subscription_token():
    return secrets.token_hex(24)


def generate_vless_uuid():
    return str(uuid.uuid4())


def generate_hy2_password():
    return secrets.token_hex(24)


def parse_env_file(path):
    values = {}
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def load_cloudflare_env(path):
    values = parse_env_file(path)
    required = (
        "CLOUDFLARE_DNS_API_TOKEN",
        "CLOUDFLARE_WORKERS_API_TOKEN",
        "CLOUDFLARE_ACCOUNT_ID",
        "CLOUDFLARE_KV_NAMESPACE_ID",
    )
    missing = [key for key in required if not values.get(key)]
    if missing:
        raise ValueError(f"missing Cloudflare env keys: {', '.join(missing)}")
    return values


def build_subscription_url(settings, subscription_token):
    return f"{settings['subscription_base_url'].rstrip('/')}/{subscription_token}"


def build_kv_value(device, content, content_type, updated_at):
    return {
        "content": content,
        "content_type": content_type,
        "client_type": device["client_type"],
        "device_name": device["device_name"],
        "device_id": device["device_id"],
        "updated_at": updated_at,
    }


def kv_request(method, path, token, body=None, content_type="application/json"):
    request = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4{path}",
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": content_type,
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        raw = response.read()
    return json.loads(raw.decode("utf-8")) if raw else None


def ensure_cloudflare_success(response):
    if response is None:
        return
    if not response.get("success", False):
        raise RuntimeError(
            f"Cloudflare API request failed: {response.get('errors') or 'unknown error'}"
        )


def kv_put_value(cloudflare_env, subscription_token, payload):
    response = kv_request(
        "PUT",
        f"/accounts/{cloudflare_env['CLOUDFLARE_ACCOUNT_ID']}/storage/kv/namespaces/"
        f"{cloudflare_env['CLOUDFLARE_KV_NAMESPACE_ID']}/values/sub:{subscription_token}",
        cloudflare_env["CLOUDFLARE_WORKERS_API_TOKEN"],
        body=json.dumps(payload).encode("utf-8"),
    )
    ensure_cloudflare_success(response)


def kv_delete_value(cloudflare_env, subscription_token):
    response = kv_request(
        "DELETE",
        f"/accounts/{cloudflare_env['CLOUDFLARE_ACCOUNT_ID']}/storage/kv/namespaces/"
        f"{cloudflare_env['CLOUDFLARE_KV_NAMESPACE_ID']}/values/sub:{subscription_token}",
        cloudflare_env["CLOUDFLARE_WORKERS_API_TOKEN"],
    )
    ensure_cloudflare_success(response)


def connect_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def row_to_device(row):
    return dict(row) if row is not None else None


def fetch_devices(conn):
    rows = conn.execute("SELECT * FROM devices ORDER BY id").fetchall()
    return [row_to_device(row) for row in rows]


def fetch_device(conn, selector):
    row = conn.execute(
        "SELECT * FROM devices WHERE device_id = ? OR device_name = ? ORDER BY id LIMIT 1",
        (selector, selector),
    ).fetchone()
    if row is None:
        raise KeyError(f"device not found: {selector}")
    return row_to_device(row)


def extract_hy2_obfs_password(base_config):
    for inbound in base_config.get("inbounds", []):
        if inbound.get("type") == "hysteria2":
            obfs = inbound.get("obfs") or {}
            password = obfs.get("password")
            if password:
                return password
    raise ValueError("hysteria2 obfs password missing from base config")


def write_generated_config(config, live_config_path):
    live_config_path = Path(live_config_path)
    live_config_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=live_config_path.parent,
        prefix="sing-box.",
        suffix=".json",
        delete=False,
    ) as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")
        return Path(handle.name)


def apply_runtime_state(
    runtime,
    settings,
    cloudflare_env,
    base_config,
    devices,
    kv_put_records,
    kv_delete_tokens,
):
    generated_config = build_sing_box_config(
        base_config,
        devices,
        settings,
        cloudflare_env["CLOUDFLARE_DNS_API_TOKEN"],
    )
    temp_config_path = write_generated_config(generated_config, runtime.live_config_path)
    live_config_path = Path(runtime.live_config_path)
    previous_config = live_config_path.read_bytes() if live_config_path.exists() else None
    replaced = False
    try:
        validate_sing_box(temp_config_path)
        temp_config_path.replace(live_config_path)
        replaced = True
        reload_sing_box()
        for token in kv_delete_tokens:
            kv_delete_value(cloudflare_env, token)
        for subscription_token, payload in kv_put_records:
            kv_put_value(cloudflare_env, subscription_token, payload)
    except Exception:
        if temp_config_path.exists():
            temp_config_path.unlink()
        if replaced:
            if previous_config is None:
                live_config_path.unlink(missing_ok=True)
            else:
                live_config_path.write_bytes(previous_config)
            reload_sing_box()
        raise
    finally:
        if temp_config_path.exists():
            temp_config_path.unlink()


def insert_device(conn, device):
    conn.execute(
        """
        INSERT INTO devices (
            device_id,
            device_name,
            client_type,
            status,
            subscription_token,
            vless_uuid,
            hy2_password,
            hy2_obfs_password,
            created_at,
            updated_at,
            revoked_at,
            last_issued_at,
            note
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            device["device_id"],
            device["device_name"],
            device["client_type"],
            device["status"],
            device["subscription_token"],
            device["vless_uuid"],
            device["hy2_password"],
            device["hy2_obfs_password"],
            device["created_at"],
            device["updated_at"],
            device["revoked_at"],
            device["last_issued_at"],
            device["note"],
        ),
    )


def issue_device(client_type, device_name, runtime):
    if client_type not in SUPPORTED_CLIENT_TYPES:
        raise ValueError(f"unsupported client_type: {client_type}")

    init_db(runtime.db_path)
    settings = load_settings(runtime.settings_path)
    base_config = load_base_config(runtime.base_config_path)
    cloudflare_env = load_cloudflare_env(runtime.cloudflare_env_path)
    now = utc_now()
    device = {
        "device_id": generate_device_id(),
        "device_name": device_name,
        "client_type": client_type,
        "status": "active",
        "subscription_token": generate_subscription_token(),
        "vless_uuid": generate_vless_uuid(),
        "hy2_password": generate_hy2_password(),
        "hy2_obfs_password": extract_hy2_obfs_password(base_config),
        "created_at": now,
        "updated_at": now,
        "revoked_at": None,
        "last_issued_at": now,
        "note": None,
    }

    conn = connect_db(runtime.db_path)
    try:
        conn.execute("BEGIN")
        insert_device(conn, device)
        devices = fetch_devices(conn)
        content, content_type = render_subscription(device, settings)
        payload = build_kv_value(device, content, content_type, device["updated_at"])
        apply_runtime_state(
            runtime,
            settings,
            cloudflare_env,
            base_config,
            devices,
            [(device["subscription_token"], payload)],
            [],
        )
        conn.commit()
        return device
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def revoke_device(selector, runtime):
    init_db(runtime.db_path)
    settings = load_settings(runtime.settings_path)
    base_config = load_base_config(runtime.base_config_path)
    cloudflare_env = load_cloudflare_env(runtime.cloudflare_env_path)
    now = utc_now()

    conn = connect_db(runtime.db_path)
    try:
        conn.execute("BEGIN")
        current = fetch_device(conn, selector)
        if current["status"] != "active":
            raise ValueError(f"device is not active: {selector}")
        conn.execute(
            """
            UPDATE devices
            SET status = ?, updated_at = ?, revoked_at = ?
            WHERE device_id = ?
            """,
            ("revoked", now, now, current["device_id"]),
        )
        devices = fetch_devices(conn)
        apply_runtime_state(
            runtime,
            settings,
            cloudflare_env,
            base_config,
            devices,
            [],
            [current["subscription_token"]],
        )
        conn.commit()
        return fetch_device(conn, selector)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def rotate_device(selector, runtime):
    init_db(runtime.db_path)
    settings = load_settings(runtime.settings_path)
    base_config = load_base_config(runtime.base_config_path)
    cloudflare_env = load_cloudflare_env(runtime.cloudflare_env_path)
    now = utc_now()

    conn = connect_db(runtime.db_path)
    try:
        conn.execute("BEGIN")
        current = fetch_device(conn, selector)
        if current["status"] != "active":
            raise ValueError(f"device is not active: {selector}")
        old_token = current["subscription_token"]
        conn.execute(
            """
            UPDATE devices
            SET subscription_token = ?,
                vless_uuid = ?,
                hy2_password = ?,
                hy2_obfs_password = ?,
                updated_at = ?,
                last_issued_at = ?,
                revoked_at = NULL
            WHERE device_id = ?
            """,
            (
                generate_subscription_token(),
                generate_vless_uuid(),
                generate_hy2_password(),
                extract_hy2_obfs_password(base_config),
                now,
                now,
                current["device_id"],
            ),
        )
        devices = fetch_devices(conn)
        rotated = fetch_device(conn, selector)
        content, content_type = render_subscription(rotated, settings)
        payload = build_kv_value(rotated, content, content_type, rotated["updated_at"])
        apply_runtime_state(
            runtime,
            settings,
            cloudflare_env,
            base_config,
            devices,
            [(rotated["subscription_token"], payload)],
            [old_token],
        )
        conn.commit()
        return rotated
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def render_all(runtime):
    init_db(runtime.db_path)
    settings = load_settings(runtime.settings_path)
    base_config = load_base_config(runtime.base_config_path)
    cloudflare_env = load_cloudflare_env(runtime.cloudflare_env_path)

    conn = connect_db(runtime.db_path)
    try:
        devices = fetch_devices(conn)
        kv_put_records = []
        for device in devices:
            if device["status"] != "active":
                continue
            content, content_type = render_subscription(device, settings)
            payload = build_kv_value(device, content, content_type, device["updated_at"])
            kv_put_records.append((device["subscription_token"], payload))
        apply_runtime_state(
            runtime,
            settings,
            cloudflare_env,
            base_config,
            devices,
            kv_put_records,
            [],
        )
        return devices
    finally:
        conn.close()


def list_devices(runtime):
    init_db(runtime.db_path)
    conn = connect_db(runtime.db_path)
    try:
        return fetch_devices(conn)
    finally:
        conn.close()


def format_device_output(device, settings):
    return "\n".join(
        [
            f"device_id: {device['device_id']}",
            f"device_name: {device['device_name']}",
            f"client_type: {device['client_type']}",
            f"subscription_url: {build_subscription_url(settings, device['subscription_token'])}",
            f"status: {device['status']}",
        ]
    )


def format_device_table(devices, settings):
    headers = [
        "DEVICE_ID",
        "CLIENT_TYPE",
        "STATUS",
        "DEVICE_NAME",
        "SUBSCRIPTION_URL",
    ]
    rows = [
        [
            device["device_id"],
            device["client_type"],
            device["status"],
            device["device_name"],
            build_subscription_url(settings, device["subscription_token"]),
        ]
        for device in devices
    ]
    widths = [
        max([len(header)] + [len(row[index]) for row in rows] or [len(header)])
        for index, header in enumerate(headers)
    ]
    lines = [
        " ".join(header.ljust(widths[index]) for index, header in enumerate(headers))
    ]
    for row in rows:
        lines.append(
            " ".join(value.ljust(widths[index]) for index, value in enumerate(row))
        )
    return "\n".join(lines)


def resolve_runtime(args):
    return RuntimePaths(
        db_path=Path(args.db_path),
        settings_path=Path(args.settings_path),
        base_config_path=Path(args.base_config_path),
        live_config_path=Path(args.live_config_path),
        cloudflare_env_path=Path(args.cloudflare_env_path),
    )


def add_common_runtime_args(parser):
    defaults = RuntimePaths()
    parser.add_argument("--db-path", default=str(defaults.db_path))
    parser.add_argument("--settings-path", default=str(defaults.settings_path))
    parser.add_argument("--base-config-path", default=str(defaults.base_config_path))
    parser.add_argument("--live-config-path", default=str(defaults.live_config_path))
    parser.add_argument("--cloudflare-env-path", default=str(defaults.cloudflare_env_path))


def cmd_issue(args):
    runtime = resolve_runtime(args)
    settings = load_settings(runtime.settings_path)
    print(format_device_output(issue_device(args.client_type, args.device_name, runtime), settings))


def cmd_revoke(args):
    runtime = resolve_runtime(args)
    settings = load_settings(runtime.settings_path)
    print(format_device_output(revoke_device(args.selector, runtime), settings))


def cmd_rotate(args):
    runtime = resolve_runtime(args)
    settings = load_settings(runtime.settings_path)
    print(format_device_output(rotate_device(args.selector, runtime), settings))


def cmd_list(args):
    runtime = resolve_runtime(args)
    settings = load_settings(runtime.settings_path)
    print(format_device_table(list_devices(runtime), settings))


def cmd_render(args):
    runtime = resolve_runtime(args)
    devices = render_all(runtime)
    active_count = sum(1 for device in devices if device["status"] == "active")
    print("status: ok")
    print(f"active_devices: {active_count}")
    print(f"db_path: {runtime.db_path}")
    print(f"live_config_path: {runtime.live_config_path}")


def build_parser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    issue_parser = subparsers.add_parser("issue")
    add_common_runtime_args(issue_parser)
    issue_parser.add_argument("client_type", choices=SUPPORTED_CLIENT_TYPES)
    issue_parser.add_argument("device_name")
    issue_parser.set_defaults(func=cmd_issue)

    revoke_parser = subparsers.add_parser("revoke")
    add_common_runtime_args(revoke_parser)
    revoke_parser.add_argument("selector")
    revoke_parser.set_defaults(func=cmd_revoke)

    rotate_parser = subparsers.add_parser("rotate")
    add_common_runtime_args(rotate_parser)
    rotate_parser.add_argument("selector")
    rotate_parser.set_defaults(func=cmd_rotate)

    list_parser = subparsers.add_parser("list")
    add_common_runtime_args(list_parser)
    list_parser.set_defaults(func=cmd_list)

    render_parser = subparsers.add_parser("render")
    add_common_runtime_args(render_parser)
    render_parser.set_defaults(func=cmd_render)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
