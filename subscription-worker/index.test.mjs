import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const WORKER_PATH = fileURLToPath(new URL("./src/index.js", import.meta.url));
const SUBSCRIPTION_HOST = "sub.example.test";
const LEGACY_TOKEN = "legacy-token";

const CLASH_RULE_SAMPLE = "payload:\n  - DOMAIN-SUFFIX,example.com\n";
const CLASH_RULE_MIRRORS = {
  direct: [
    "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/direct.txt",
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt",
  ],
  cncidr: [
    "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/cncidr.txt",
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt",
  ],
};
const SHADOWROCKET_RULE_MIRRORS = [
  "https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/release/sr_top500_whitelist_ad.conf",
  "https://cdn.jsdelivr.net/gh/Johnshall/Shadowrocket-ADBlock-Rules-Forever@release/sr_top500_whitelist_ad.conf",
];
const SHADOWROCKET_RULE_SAMPLE = `
[General]
dns-server = https://dns.alidns.com/dns-query

[Rule]
DOMAIN-SUFFIX,ads.example,Reject
DOMAIN-SUFFIX,example.cn,Direct
DOMAIN-SUFFIX,telegram.org,Proxy
FINAL,PROXY
`.trimStart();

function createFetchStub({
  clashRule = CLASH_RULE_SAMPLE,
  shadowrocketRule = SHADOWROCKET_RULE_SAMPLE,
  ruleResponses = {},
} = {}) {
  const fetchStub = async (input) => {
    const url = typeof input === "string" ? input : input.url;
    if (url.includes("clash-rules")) {
      const configuredResponse = ruleResponses[url];
      if (configuredResponse instanceof Error) {
        throw configuredResponse;
      }
      if (configuredResponse !== undefined) {
        if (typeof configuredResponse === "string") {
          return new Response(configuredResponse);
        }

        return new Response(configuredResponse.body ?? "", {
          status: configuredResponse.status ?? 200,
          headers: configuredResponse.headers,
        });
      }

      return new Response(clashRule);
    }
    if (url.includes("Shadowrocket-ADBlock-Rules-Forever")) {
      const configuredResponse = ruleResponses[url];
      if (configuredResponse instanceof Error) {
        throw configuredResponse;
      }
      if (configuredResponse !== undefined) {
        if (typeof configuredResponse === "string") {
          return new Response(configuredResponse);
        }

        return new Response(configuredResponse.body ?? "", {
          status: configuredResponse.status ?? 200,
          headers: configuredResponse.headers,
        });
      }

      return new Response(shadowrocketRule);
    }
    return new Response("upstream unavailable", { status: 502 });
  };

  return fetchStub;
}

function createKvNamespace(entries = {}) {
  const store = new Map(Object.entries(entries));
  return {
    async get(key) {
      return store.get(key) ?? null;
    },
  };
}

function createConsoleStub() {
  const errors = [];
  return {
    ...console,
    errors,
    error(...args) {
      errors.push(args);
    },
    warn() {},
  };
}

async function loadWorker(fetchImpl, consoleImpl = createConsoleStub()) {
  const source = (await readFile(WORKER_PATH, "utf8")).replace(
    /export\s+default\s+/,
    "module.exports.default = ",
  );
  const module = { exports: {} };
  const context = vm.createContext({
    console: consoleImpl,
    fetch: fetchImpl,
    Headers,
    Response,
    URL,
    module,
    exports: module.exports,
  });
  vm.runInContext(source, context, { filename: WORKER_PATH });
  return module.exports.default;
}

test("subscription token returns stored content with its content type", async () => {
  const worker = await loadWorker(createFetchStub());
  const env = {
    SUBSCRIPTIONS: createKvNamespace({
      "sub:alpha": JSON.stringify({
        content: "mixed-port: 7890\n",
        content_type: "text/yaml; charset=utf-8",
      }),
    }),
  };

  const response = await worker.fetch(new Request("https://sub.example.test/s/alpha"), env);

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "text/yaml; charset=utf-8");
  assert.equal(await response.text(), "mixed-port: 7890\n");
});

test("missing subscription token returns 404", async () => {
  const worker = await loadWorker(createFetchStub());
  const env = { SUBSCRIPTIONS: createKvNamespace() };
  const response = await worker.fetch(new Request("https://sub.example.test/s/missing"), env);

  assert.equal(response.status, 404);
});

test("malformed subscription JSON returns 500", async () => {
  const worker = await loadWorker(createFetchStub());
  const env = {
    SUBSCRIPTIONS: createKvNamespace({
      "sub:broken": "{",
    }),
  };

  const response = await worker.fetch(new Request("https://sub.example.test/s/broken"), env);

  assert.equal(response.status, 500);
});

test("empty subscription JSON string returns 500", async () => {
  const worker = await loadWorker(createFetchStub());
  const env = {
    SUBSCRIPTIONS: createKvNamespace({
      "sub:broken": "",
    }),
  };

  const response = await worker.fetch(new Request("https://sub.example.test/s/broken"), env);

  assert.equal(response.status, 500);
});

test("invalid subscription record shape returns 500", async () => {
  const worker = await loadWorker(createFetchStub());
  const env = {
    SUBSCRIPTIONS: createKvNamespace({
      "sub:broken": JSON.stringify({
        content: 42,
      }),
    }),
  };

  const response = await worker.fetch(new Request("https://sub.example.test/s/broken"), env);

  assert.equal(response.status, 500);
});

test("missing subscription KV binding returns 500", async () => {
  const worker = await loadWorker(createFetchStub());
  const response = await worker.fetch(new Request("https://sub.example.test/s/alpha"), {});

  assert.equal(response.status, 500);
});

test("subscription response falls back to text/plain when content type is missing", async () => {
  const worker = await loadWorker(createFetchStub());
  const env = {
    SUBSCRIPTIONS: createKvNamespace({
      "sub:alpha": JSON.stringify({
        content: "mixed-port: 7890\n",
      }),
    }),
  };

  const response = await worker.fetch(new Request("https://sub.example.test/s/alpha"), env);

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "text/plain; charset=utf-8");
});

test("subscription response falls back to text/plain when content type is blank", async () => {
  const worker = await loadWorker(createFetchStub());
  const env = {
    SUBSCRIPTIONS: createKvNamespace({
      "sub:alpha": JSON.stringify({
        content: "mixed-port: 7890\n",
        content_type: "   ",
      }),
    }),
  };

  const response = await worker.fetch(new Request("https://sub.example.test/s/alpha"), env);

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "text/plain; charset=utf-8");
});

test("shared clash rule paths proxy upstream rule content", async () => {
  const worker = await loadWorker(createFetchStub());
  const response = await worker.fetch(new Request("https://sub.example.test/rules/direct.txt"));

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "text/plain; charset=utf-8");
  assert.match(await response.text(), /DOMAIN-SUFFIX,example\.com/);
});

test("rule responses strip upstream entity headers", async () => {
  const worker = await loadWorker(
    createFetchStub({
      ruleResponses: {
        [CLASH_RULE_MIRRORS.direct[0]]: {
          body: CLASH_RULE_SAMPLE,
          headers: {
            "content-length": "999",
            "content-encoding": "gzip",
            etag: '"abc123"',
            "last-modified": "Wed, 01 Jan 2025 00:00:00 GMT",
            "x-extra-header": "keep-me?",
          },
        },
      },
    }),
  );

  const response = await worker.fetch(new Request("https://sub.example.test/rules/direct.txt"));

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "text/plain; charset=utf-8");
  assert.equal(response.headers.get("cache-control"), "public, max-age=21600");
  assert.equal(response.headers.get("content-length"), null);
  assert.equal(response.headers.get("content-encoding"), null);
  assert.equal(response.headers.get("etag"), null);
  assert.equal(response.headers.get("last-modified"), null);
  assert.equal(response.headers.get("x-extra-header"), null);
});

test("shared shadowrocket rule paths transform upstream payloads", async () => {
  const worker = await loadWorker(
    createFetchStub(),
  );
  const response = await worker.fetch(
    new Request("https://sub.example.test/shadowrocket-rules/proxy.list"),
  );

  assert.equal(response.status, 200);
  assert.equal(await response.text(), "DOMAIN-SUFFIX,telegram.org\n");
});

test("serves shared Shadowrocket module without device secrets", async () => {
  const worker = await loadWorker(createFetchStub());
  const response = await worker.fetch(
    new Request("https://sub.example.test/shadowrocket/module.conf"),
  );

  assert.equal(response.status, 200);
  const text = await response.text();
  assert.match(text, /\[General\]/);
  assert.match(text, /\[Rule\]/);
  assert.match(text, /shadowrocket-rules\/reject\.list/);
  assert.match(text, /shadowrocket-rules\/direct\.list/);
  assert.match(text, /shadowrocket-rules\/proxy\.list/);
  assert.doesNotMatch(text, /\[Proxy\]/);
  assert.doesNotMatch(text, /323e4567-e89b-12d3-a456-426614174000/);
});

test("shadowrocket rule responses strip upstream entity headers after transformation", async () => {
  const worker = await loadWorker(
    createFetchStub({
      ruleResponses: {
        [SHADOWROCKET_RULE_MIRRORS[0]]: {
          body: SHADOWROCKET_RULE_SAMPLE,
          headers: {
            "content-length": "1234",
            "content-encoding": "gzip",
            etag: '"shadowrocket-upstream"',
            "last-modified": "Wed, 01 Jan 2025 00:00:00 GMT",
          },
        },
      },
    }),
  );

  const response = await worker.fetch(
    new Request("https://sub.example.test/shadowrocket-rules/reject.list"),
  );

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-type"), "text/plain; charset=utf-8");
  assert.equal(response.headers.get("cache-control"), "public, max-age=21600");
  assert.equal(response.headers.get("content-length"), null);
  assert.equal(response.headers.get("content-encoding"), null);
  assert.equal(response.headers.get("etag"), null);
  assert.equal(response.headers.get("last-modified"), null);
  assert.equal(await response.text(), "DOMAIN-SUFFIX,ads.example\n");
});

test("rule fetch retries the second mirror when the first mirror throws", async () => {
  const worker = await loadWorker(
    createFetchStub({
      ruleResponses: {
        [CLASH_RULE_MIRRORS.direct[0]]: new Error("mirror 1 failed"),
        [CLASH_RULE_MIRRORS.direct[1]]: "payload:\n  - DOMAIN,example.org\n",
      },
    }),
  );

  const response = await worker.fetch(new Request("https://sub.example.test/rules/direct.txt"));

  assert.equal(response.status, 200);
  assert.match(await response.text(), /DOMAIN,example\.org/);
});

test("rule fetch returns 502 when all mirrors throw", async () => {
  const worker = await loadWorker(
    createFetchStub({
      ruleResponses: {
        [CLASH_RULE_MIRRORS.direct[0]]: new Error("mirror 1 failed"),
        [CLASH_RULE_MIRRORS.direct[1]]: new Error("mirror 2 failed"),
      },
    }),
  );

  const response = await worker.fetch(new Request("https://sub.example.test/rules/direct.txt"));

  assert.equal(response.status, 502);
});

test("shadowrocket rule fetch retries the second Johnshall mirror when the first mirror throws", async () => {
  const worker = await loadWorker(
    createFetchStub({
      ruleResponses: {
        [SHADOWROCKET_RULE_MIRRORS[0]]: new Error("mirror 1 failed"),
        [SHADOWROCKET_RULE_MIRRORS[1]]: SHADOWROCKET_RULE_SAMPLE,
      },
    }),
  );

  const response = await worker.fetch(
    new Request("https://sub.example.test/shadowrocket-rules/direct.list"),
  );

  assert.equal(response.status, 200);
  assert.equal(await response.text(), "DOMAIN-SUFFIX,example.cn\n");
});

test("subscription error logging redacts token context", async () => {
  const consoleStub = createConsoleStub();
  const worker = await loadWorker(createFetchStub(), consoleStub);
  const token = "sensitive-token-1234567890";
  const env = {
    SUBSCRIPTIONS: createKvNamespace({
      [`sub:${token}`]: "{",
    }),
  };

  const response = await worker.fetch(new Request(`https://sub.example.test/s/${token}`), env);
  const loggedOutput = consoleStub.errors
    .flat()
    .map((value) => (value instanceof Error ? value.message : String(value)))
    .join("\n");

  assert.equal(response.status, 500);
  assert.match(loggedOutput, /sensit\.\.\./);
  assert.doesNotMatch(loggedOutput, new RegExp(token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("unrelated paths and legacy subscription URLs return 404", async () => {
  const worker = await loadWorker(createFetchStub());
  const env = {
    SUBSCRIPTIONS: createKvNamespace({
      "sub:alpha": JSON.stringify({
        content: "mixed-port: 7890\n",
        content_type: "text/yaml; charset=utf-8",
      }),
    }),
  };

  const unrelatedResponse = await worker.fetch(new Request("https://sub.example.test/foo"), env);
  const legacyResponse = await worker.fetch(
    new Request(`https://sub.example.test/${LEGACY_TOKEN}/mihomo-desktop.yaml`),
    env,
  );

  assert.equal(unrelatedResponse.status, 404);
  assert.equal(legacyResponse.status, 404);
});
