import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("proxy_issuer.py")
SPEC = importlib.util.spec_from_file_location("proxy_issuer", MODULE_PATH)
proxy_issuer = importlib.util.module_from_spec(SPEC)
sys.modules["proxy_issuer"] = proxy_issuer
SPEC.loader.exec_module(proxy_issuer)


SAMPLE_SETTINGS = {
    "subscription_base_url": "https://sub.example.com/s",
    "mihomo_rule_base_url": "https://sub.example.com/rules",
    "shadowrocket_rule_base_url": "https://sub.example.com/shadowrocket-rules",
    "proxy_server": "proxy.example.com",
    "reality_server_name": "www.microsoft.com",
    "reality_public_key": "hNwlIHs3EKLLHiVsCppcs_hbVJ3up-HYQfBeHqjC2l8",
    "reality_short_id": "0123456789abcdef",
    "hysteria2_sni": "proxy.example.com",
    "hysteria2_alpn": ["h3"],
}

DESKTOP_DEVICE = {
    "device_id": "dev-desktop-001",
    "device_name": "macbook-pro",
    "client_type": "mihomo-desktop",
    "status": "active",
    "subscription_token": "desktop-token",
    "vless_uuid": "123e4567-e89b-12d3-a456-426614174000",
    "hy2_password": "hy2-password-desktop",
    "hy2_obfs_password": "hy2-obfs-desktop",
}

SERVER_DEVICE = {
    "device_id": "dev-server-001",
    "device_name": "server-box",
    "client_type": "mihomo-server",
    "status": "active",
    "subscription_token": "server-token",
    "vless_uuid": "223e4567-e89b-12d3-a456-426614174000",
    "hy2_password": "hy2-password-server",
    "hy2_obfs_password": "hy2-obfs-server",
}

SHADOWROCKET_DEVICE = {
    "device_id": "dev-phone-001",
    "device_name": "iphone-15",
    "client_type": "shadowrocket",
    "status": "active",
    "subscription_token": "phone-token",
    "vless_uuid": "323e4567-e89b-12d3-a456-426614174000",
    "hy2_password": "hy2-password-phone",
    "hy2_obfs_password": "hy2-obfs-phone",
}

REVOKED_DEVICE = {
    "device_id": "dev-revoked-001",
    "device_name": "revoked-device",
    "client_type": "shadowrocket",
    "status": "revoked",
    "subscription_token": "revoked-token",
    "vless_uuid": "423e4567-e89b-12d3-a456-426614174000",
    "hy2_password": "hy2-password-revoked",
    "hy2_obfs_password": "hy2-obfs-revoked",
}


class InitDbTests(unittest.TestCase):
    INSERT_DEVICE_SQL = """
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
    """

    def insert_device(self, conn, row):
        conn.execute(self.INSERT_DEVICE_SQL, row)

    def test_init_db_creates_devices_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "devices.db"

            proxy_issuer.init_db(db_path)

            conn = sqlite3.connect(db_path)
            try:
                table_names = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                columns = {
                    row[1]
                    for row in conn.execute("PRAGMA table_info(devices)").fetchall()
                }
            finally:
                conn.close()

            self.assertIn("devices", table_names)
            self.assertEqual(
                columns,
                {
                    "id",
                    "device_id",
                    "device_name",
                    "client_type",
                    "status",
                    "subscription_token",
                    "vless_uuid",
                    "hy2_password",
                    "hy2_obfs_password",
                    "created_at",
                    "updated_at",
                    "revoked_at",
                    "last_issued_at",
                    "note",
                },
            )

    def test_init_db_marks_planned_columns_not_null(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "devices.db"

            proxy_issuer.init_db(db_path)

            conn = sqlite3.connect(db_path)
            try:
                table_info = conn.execute("PRAGMA table_info(devices)").fetchall()
            finally:
                conn.close()

            not_null_by_column = {row[1]: bool(row[3]) for row in table_info}

            self.assertTrue(not_null_by_column["vless_uuid"])
            self.assertTrue(not_null_by_column["hy2_password"])
            self.assertTrue(not_null_by_column["hy2_obfs_password"])
            self.assertTrue(not_null_by_column["last_issued_at"])

    def test_init_db_enforces_unique_device_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "devices.db"
            proxy_issuer.init_db(db_path)

            row = (
                "dev-test-001",
                "macbook-pro",
                "mihomo-desktop",
                "active",
                "token-001",
                "123e4567-e89b-12d3-a456-426614174000",
                "hy2-password-1",
                "hy2-obfs-1",
                "2026-04-16T00:00:00Z",
                "2026-04-16T00:00:00Z",
                None,
                "2026-04-16T00:00:00Z",
                "first",
            )
            duplicate_name_row = (
                "dev-test-002",
                "macbook-pro",
                "shadowrocket",
                "active",
                "token-002",
                "223e4567-e89b-12d3-a456-426614174000",
                "hy2-password-2",
                "hy2-obfs-2",
                "2026-04-16T00:00:01Z",
                "2026-04-16T00:00:01Z",
                None,
                "2026-04-16T00:00:01Z",
                "second",
            )

            conn = sqlite3.connect(db_path)
            try:
                self.insert_device(conn, row)
                conn.commit()

                with self.assertRaises(sqlite3.IntegrityError):
                    self.insert_device(conn, duplicate_name_row)
            finally:
                conn.close()

    def test_init_db_enforces_unique_device_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "devices.db"
            proxy_issuer.init_db(db_path)

            row = (
                "dev-test-001",
                "macbook-pro",
                "mihomo-desktop",
                "active",
                "token-001",
                "123e4567-e89b-12d3-a456-426614174000",
                "hy2-password-1",
                "hy2-obfs-1",
                "2026-04-16T00:00:00Z",
                "2026-04-16T00:00:00Z",
                None,
                "2026-04-16T00:00:00Z",
                "first",
            )
            duplicate_device_id_row = (
                "dev-test-001",
                "iphone-15",
                "shadowrocket",
                "active",
                "token-002",
                "223e4567-e89b-12d3-a456-426614174000",
                "hy2-password-2",
                "hy2-obfs-2",
                "2026-04-16T00:00:01Z",
                "2026-04-16T00:00:01Z",
                None,
                "2026-04-16T00:00:01Z",
                "second",
            )

            conn = sqlite3.connect(db_path)
            try:
                self.insert_device(conn, row)
                conn.commit()

                with self.assertRaises(sqlite3.IntegrityError):
                    self.insert_device(conn, duplicate_device_id_row)
            finally:
                conn.close()

    def test_init_db_enforces_unique_subscription_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "devices.db"
            proxy_issuer.init_db(db_path)

            row = (
                "dev-test-001",
                "macbook-pro",
                "mihomo-desktop",
                "active",
                "token-001",
                "123e4567-e89b-12d3-a456-426614174000",
                "hy2-password-1",
                "hy2-obfs-1",
                "2026-04-16T00:00:00Z",
                "2026-04-16T00:00:00Z",
                None,
                "2026-04-16T00:00:00Z",
                "first",
            )
            duplicate_subscription_token_row = (
                "dev-test-002",
                "iphone-15",
                "shadowrocket",
                "active",
                "token-001",
                "223e4567-e89b-12d3-a456-426614174000",
                "hy2-password-2",
                "hy2-obfs-2",
                "2026-04-16T00:00:01Z",
                "2026-04-16T00:00:01Z",
                None,
                "2026-04-16T00:00:01Z",
                "second",
            )

            conn = sqlite3.connect(db_path)
            try:
                self.insert_device(conn, row)
                conn.commit()

                with self.assertRaises(sqlite3.IntegrityError):
                    self.insert_device(conn, duplicate_subscription_token_row)
            finally:
                conn.close()


class ConfigLoadTests(unittest.TestCase):
    def test_repository_base_config_path_points_to_templates_copy(self):
        path = proxy_issuer.repository_base_config_path()

        self.assertEqual(path.name, "config.base.json")
        self.assertEqual(path.parent.name, "templates")
        self.assertTrue(path.is_file())

    def test_repository_base_config_template_does_not_embed_live_environment_values(self):
        template_text = proxy_issuer.repository_base_config_path().read_text(
            encoding="utf-8"
        )

        self.assertNotIn("proxy.example.com", template_text)
        self.assertNotIn("GJ2m8AX2f0NsOZVzNu1AiFf50cmt1IIudS4unV5P7UI", template_text)
        self.assertIn("BOOTSTRAP_RENDERS_PROXY_HOST", template_text)
        self.assertIn("BOOTSTRAP_RENDERS_REALITY_PRIVATE_KEY", template_text)

    def test_load_base_config_reads_base_template(self):
        path = proxy_issuer.repository_base_config_path()

        config = proxy_issuer.load_base_config(path)

        self.assertEqual(config["log"], {"level": "warn", "timestamp": True})
        self.assertEqual(len(config["inbounds"]), 2)
        self.assertEqual(config["inbounds"][0]["tag"], "vless-reality-in")
        self.assertEqual(config["inbounds"][0]["users"], [])
        self.assertEqual(config["inbounds"][1]["tag"], "hy2-in")
        self.assertEqual(config["inbounds"][1]["users"], [])
        self.assertEqual(config["inbounds"][1]["obfs"]["type"], "salamander")
        self.assertTrue(config["inbounds"][1]["obfs"]["password"])

    def test_load_settings_reads_json_from_temp_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            expected = {
                "subscription_base_url": "https://sub.example.com/s",
                "proxy_server": "proxy.example.com",
            }
            path.write_text(json.dumps(expected), encoding="utf-8")

            self.assertEqual(proxy_issuer.load_settings(path), expected)

    def test_runtime_paths_defaults_still_target_deployed_locations(self):
        runtime = proxy_issuer.RuntimePaths()

        self.assertEqual(runtime.base_config_path, Path("/etc/sing-box/config.base.json"))
        self.assertEqual(runtime.settings_path, Path("/etc/proxy-issuer/settings.json"))
        self.assertEqual(
            runtime.cloudflare_env_path, Path("/etc/proxy-issuer/cloudflare.env")
        )


class RendererTests(unittest.TestCase):
    def test_render_mihomo_desktop_contains_live_shape_markers(self):
        rendered = proxy_issuer.render_mihomo_desktop(DESKTOP_DEVICE, SAMPLE_SETTINGS)

        self.assertIn("log-level: info", rendered)
        self.assertIn("unified-delay: true", rendered)
        self.assertIn("global-client-fingerprint: chrome", rendered)
        self.assertIn("store-fake-ip: true", rendered)
        self.assertIn("listen: 127.0.0.1:1053", rendered)
        self.assertIn("enhanced-mode: fake-ip", rendered)
        self.assertIn("fake-ip-range: 198.18.0.1/16", rendered)
        self.assertIn("proxy-server-nameserver:", rendered)
        self.assertIn("tun:", rendered)
        self.assertIn("stack: mixed", rendered)
        self.assertIn("AUTO", rendered)
        self.assertIn("https://cp.cloudflare.com/generate_204", rendered)
        self.assertIn("SG VLESS Reality", rendered)
        self.assertIn("https://sub.example.com/rules/reject.txt", rendered)
        self.assertIn("https://sub.example.com/rules/applications.txt", rendered)
        self.assertIn(DESKTOP_DEVICE["vless_uuid"], rendered)
        self.assertIn(DESKTOP_DEVICE["hy2_password"], rendered)
        self.assertIn(DESKTOP_DEVICE["hy2_obfs_password"], rendered)
        self.assertIn("MATCH,PROXY", rendered)

    def test_render_mihomo_server_omits_tun_and_fake_ip_listener(self):
        rendered = proxy_issuer.render_mihomo_server(SERVER_DEVICE, SAMPLE_SETTINGS)

        self.assertNotIn("tun:", rendered)
        self.assertIn("store-selected: true", rendered)
        self.assertIn("enhanced-mode: redir-host", rendered)
        self.assertNotIn("listen: 127.0.0.1:1053", rendered)
        self.assertIn("https://sub.example.com/rules/proxy.txt", rendered)
        self.assertIn("MATCH,PROXY", rendered)

    def test_render_shadowrocket_contains_sections_credentials_and_shared_rules(self):
        rendered = proxy_issuer.render_shadowrocket(
            SHADOWROCKET_DEVICE, SAMPLE_SETTINGS
        )

        self.assertIn("[General]", rendered)
        self.assertIn("ipv6 = true", rendered)
        self.assertIn("[Proxy Group]", rendered)
        self.assertIn("AUTO = url-test", rendered)
        self.assertIn(SHADOWROCKET_DEVICE["vless_uuid"], rendered)
        self.assertIn(SHADOWROCKET_DEVICE["hy2_password"], rendered)
        self.assertIn(SHADOWROCKET_DEVICE["hy2_obfs_password"], rendered)
        self.assertIn(
            "RULE-SET,https://sub.example.com/shadowrocket-rules/reject.list,REJECT",
            rendered,
        )
        self.assertIn("IP-CIDR,192.168.0.0/16,DIRECT", rendered)
        self.assertIn("FINAL,PROXY", rendered)

    def test_render_subscription_dispatches_content_type_by_client(self):
        desktop_content, desktop_content_type = proxy_issuer.render_subscription(
            DESKTOP_DEVICE, SAMPLE_SETTINGS
        )
        shadowrocket_content, shadowrocket_content_type = (
            proxy_issuer.render_subscription(SHADOWROCKET_DEVICE, SAMPLE_SETTINGS)
        )

        self.assertIn("mixed-port: 7890", desktop_content)
        self.assertEqual(desktop_content_type, "text/yaml; charset=utf-8")
        self.assertIn("[General]", shadowrocket_content)
        self.assertEqual(
            shadowrocket_content_type,
            "text/plain; charset=utf-8",
        )


class ConfigGenerationTests(unittest.TestCase):
    def test_build_sing_box_config_uses_active_devices_only_and_injects_token(self):
        base_config = proxy_issuer.load_base_config(
            proxy_issuer.repository_base_config_path()
        )

        config = proxy_issuer.build_sing_box_config(
            base_config,
            [DESKTOP_DEVICE, SERVER_DEVICE, REVOKED_DEVICE],
            SAMPLE_SETTINGS,
            "dns-token-new",
        )

        vless_inbound = next(
            inbound for inbound in config["inbounds"] if inbound["type"] == "vless"
        )
        hy2_inbound = next(
            inbound
            for inbound in config["inbounds"]
            if inbound["type"] == "hysteria2"
        )

        self.assertEqual(vless_inbound["tag"], "vless-reality-in")
        self.assertEqual(
            [user["name"] for user in vless_inbound["users"]],
            ["macbook-pro", "server-box"],
        )
        self.assertEqual(
            [user["uuid"] for user in vless_inbound["users"]],
            [DESKTOP_DEVICE["vless_uuid"], SERVER_DEVICE["vless_uuid"]],
        )
        self.assertTrue(
            all(user["flow"] == "xtls-rprx-vision" for user in vless_inbound["users"])
        )

        self.assertEqual(hy2_inbound["tag"], "hy2-in")
        self.assertEqual(
            [user["password"] for user in hy2_inbound["users"]],
            [DESKTOP_DEVICE["hy2_password"], SERVER_DEVICE["hy2_password"]],
        )
        self.assertEqual(hy2_inbound["obfs"]["type"], "salamander")
        self.assertEqual(
            hy2_inbound["obfs"]["password"],
            proxy_issuer.extract_hy2_obfs_password(base_config),
        )
        self.assertEqual(
            hy2_inbound["tls"]["acme"]["dns01_challenge"]["api_token"],
            "dns-token-new",
        )
        self.assertEqual(hy2_inbound["tls"]["server_name"], "proxy.example.com")

    def test_validate_sing_box_uses_run_checked(self):
        with mock.patch.object(proxy_issuer, "run_checked") as mocked:
            proxy_issuer.validate_sing_box("/tmp/test-sing-box.json")

        mocked.assert_called_once_with(
            ["sing-box", "check", "-c", "/tmp/test-sing-box.json"]
        )

    def test_reload_sing_box_uses_run_checked(self):
        with mock.patch.object(proxy_issuer, "run_checked") as mocked:
            proxy_issuer.reload_sing_box()

        mocked.assert_called_once_with(["systemctl", "reload", "sing-box"])


class IssuerFlowTests(unittest.TestCase):
    def make_runtime(self, tmp_path):
        settings_path = tmp_path / "settings.json"
        settings_path.write_text(json.dumps(SAMPLE_SETTINGS), encoding="utf-8")

        cloudflare_env_path = tmp_path / "cloudflare.env"
        cloudflare_env_path.write_text(
            "\n".join(
                [
                    "CLOUDFLARE_DNS_API_TOKEN=test-dns-token",
                    "CLOUDFLARE_WORKERS_API_TOKEN=test-workers-token",
                    "CLOUDFLARE_ACCOUNT_ID=test-account",
                    "CLOUDFLARE_KV_NAMESPACE_ID=test-namespace",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        base_config_path = tmp_path / "config.base.json"
        base_config_path.write_text(
            proxy_issuer.repository_base_config_path().read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        live_config_path = tmp_path / "config.json"
        live_config_path.write_text(
            base_config_path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        return proxy_issuer.RuntimePaths(
            db_path=tmp_path / "devices.db",
            settings_path=settings_path,
            base_config_path=base_config_path,
            live_config_path=live_config_path,
            cloudflare_env_path=cloudflare_env_path,
        )

    def test_build_kv_value_contains_content_metadata(self):
        payload = proxy_issuer.build_kv_value(
            DESKTOP_DEVICE,
            "mixed-port: 7890\nmode: rule\n",
            "text/yaml; charset=utf-8",
            "2026-04-16T00:00:00Z",
        )

        self.assertEqual(payload["client_type"], "mihomo-desktop")
        self.assertEqual(payload["device_name"], "macbook-pro")
        self.assertEqual(payload["content_type"], "text/yaml; charset=utf-8")
        self.assertIn("mixed-port: 7890", payload["content"])

    def test_load_cloudflare_env_requires_expected_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / "cloudflare.env"
            env_path.write_text("CLOUDFLARE_DNS_API_TOKEN=x\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                proxy_issuer.load_cloudflare_env(env_path)

    def test_issue_device_persists_row_and_publishes_subscription(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.make_runtime(Path(tmp))
            with mock.patch.object(
                proxy_issuer, "validate_sing_box"
            ) as validate_mock, mock.patch.object(
                proxy_issuer, "reload_sing_box"
            ) as reload_mock, mock.patch.object(
                proxy_issuer, "kv_put_value"
            ) as kv_put_mock, mock.patch.object(
                proxy_issuer, "generate_device_id", return_value="dev_20260416_abcd1234"
            ), mock.patch.object(
                proxy_issuer, "generate_subscription_token", return_value="subtoken123"
            ), mock.patch.object(
                proxy_issuer,
                "generate_vless_uuid",
                return_value="11111111-1111-1111-1111-111111111111",
            ), mock.patch.object(
                proxy_issuer, "generate_hy2_password", return_value="hy2-secret"
            ), mock.patch.object(
                proxy_issuer, "utc_now", return_value="2026-04-16T00:00:00Z"
            ):
                device = proxy_issuer.issue_device(
                    "mihomo-desktop", "macos-main", runtime
                )

            self.assertEqual(device["device_id"], "dev_20260416_abcd1234")
            self.assertEqual(device["subscription_token"], "subtoken123")
            validate_mock.assert_called_once()
            reload_mock.assert_called_once()
            kv_put_mock.assert_called_once()

            conn = sqlite3.connect(runtime.db_path)
            try:
                row = conn.execute(
                    "SELECT device_name, status, subscription_token FROM devices"
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(row, ("macos-main", "active", "subtoken123"))

    def test_revoke_device_marks_status_and_deletes_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.make_runtime(Path(tmp))
            with mock.patch.object(proxy_issuer, "validate_sing_box"), mock.patch.object(
                proxy_issuer, "reload_sing_box"
            ), mock.patch.object(proxy_issuer, "kv_put_value"), mock.patch.object(
                proxy_issuer, "generate_device_id", return_value="dev_20260416_abcd1234"
            ), mock.patch.object(
                proxy_issuer, "generate_subscription_token", return_value="subtoken123"
            ), mock.patch.object(
                proxy_issuer,
                "generate_vless_uuid",
                return_value="11111111-1111-1111-1111-111111111111",
            ), mock.patch.object(
                proxy_issuer, "generate_hy2_password", return_value="hy2-secret"
            ), mock.patch.object(
                proxy_issuer, "utc_now", return_value="2026-04-16T00:00:00Z"
            ):
                proxy_issuer.issue_device("mihomo-desktop", "macos-main", runtime)

            with mock.patch.object(
                proxy_issuer, "validate_sing_box"
            ), mock.patch.object(
                proxy_issuer, "reload_sing_box"
            ) as reload_mock, mock.patch.object(
                proxy_issuer, "kv_delete_value"
            ) as kv_delete_mock, mock.patch.object(
                proxy_issuer, "utc_now", return_value="2026-04-16T01:00:00Z"
            ):
                device = proxy_issuer.revoke_device("macos-main", runtime)

            self.assertEqual(device["status"], "revoked")
            reload_mock.assert_called_once()
            kv_delete_mock.assert_called_once_with(mock.ANY, "subtoken123")

    def test_rotate_device_reissues_credentials_and_replaces_subscription(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self.make_runtime(Path(tmp))
            with mock.patch.object(proxy_issuer, "validate_sing_box"), mock.patch.object(
                proxy_issuer, "reload_sing_box"
            ), mock.patch.object(proxy_issuer, "kv_put_value"), mock.patch.object(
                proxy_issuer, "generate_device_id", return_value="dev_20260416_abcd1234"
            ), mock.patch.object(
                proxy_issuer, "generate_subscription_token", return_value="subtoken123"
            ), mock.patch.object(
                proxy_issuer,
                "generate_vless_uuid",
                return_value="11111111-1111-1111-1111-111111111111",
            ), mock.patch.object(
                proxy_issuer, "generate_hy2_password", return_value="hy2-secret"
            ), mock.patch.object(
                proxy_issuer, "utc_now", return_value="2026-04-16T00:00:00Z"
            ):
                proxy_issuer.issue_device("mihomo-desktop", "macos-main", runtime)

            with mock.patch.object(
                proxy_issuer, "validate_sing_box"
            ), mock.patch.object(
                proxy_issuer, "reload_sing_box"
            ), mock.patch.object(
                proxy_issuer, "kv_put_value"
            ) as kv_put_mock, mock.patch.object(
                proxy_issuer, "kv_delete_value"
            ) as kv_delete_mock, mock.patch.object(
                proxy_issuer, "generate_subscription_token", return_value="subtoken456"
            ), mock.patch.object(
                proxy_issuer,
                "generate_vless_uuid",
                return_value="22222222-2222-2222-2222-222222222222",
            ), mock.patch.object(
                proxy_issuer, "generate_hy2_password", return_value="hy2-rotated"
            ), mock.patch.object(
                proxy_issuer, "utc_now", return_value="2026-04-16T02:00:00Z"
            ):
                device = proxy_issuer.rotate_device("macos-main", runtime)

            self.assertEqual(device["subscription_token"], "subtoken456")
            self.assertEqual(device["vless_uuid"], "22222222-2222-2222-2222-222222222222")
            kv_delete_mock.assert_called_once_with(mock.ANY, "subtoken123")
            kv_put_mock.assert_called_once()

    def test_format_device_table_emits_stable_columns(self):
        table = proxy_issuer.format_device_table(
            [DESKTOP_DEVICE, SERVER_DEVICE], SAMPLE_SETTINGS
        )

        self.assertIn("DEVICE_ID", table)
        self.assertIn("CLIENT_TYPE", table)
        self.assertIn("SUBSCRIPTION_URL", table)
        self.assertIn("https://sub.example.com/s/desktop-token", table)


if __name__ == "__main__":
    unittest.main()
