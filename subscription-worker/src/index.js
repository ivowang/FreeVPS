const RULES = {
  reject: { behavior: "domain" },
  icloud: { behavior: "domain" },
  apple: { behavior: "domain" },
  google: { behavior: "domain" },
  proxy: { behavior: "domain" },
  direct: { behavior: "domain" },
  private: { behavior: "domain" },
  telegramcidr: { behavior: "ipcidr" },
  cncidr: { behavior: "ipcidr" },
  lancidr: { behavior: "ipcidr" },
  applications: { behavior: "classical" },
};
const SHADOWROCKET_RULE_BUCKETS = new Set(["reject", "direct", "proxy"]);

function notFound() {
  return new Response("Not found", {
    status: 404,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function internalError() {
  return new Response("Internal server error", {
    status: 500,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function redactTokenForLog(token) {
  if (typeof token !== "string" || !token) {
    return "<redacted>";
  }

  return `${token.slice(0, 6)}...`;
}

function subscriptionPathToken(pathname) {
  const match = pathname.match(/^\/s\/([^/]+)$/);
  return match ? match[1] : null;
}

function rulePathName(pathname) {
  const match = pathname.match(/^\/rules\/([^/]+)\.txt$/);
  return match ? match[1] : null;
}

function shadowrocketRulePathName(pathname) {
  const match = pathname.match(/^\/shadowrocket-rules\/([^/]+)\.list$/);
  return match ? match[1] : null;
}

function shadowrocketModulePath(pathname) {
  return pathname === "/shadowrocket/module.conf";
}

function upstreamUrls(name) {
  return [
    `https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/${name}.txt`,
    `https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/${name}.txt`,
  ];
}

function shadowrocketUpstreamUrls() {
  return [
    "https://raw.githubusercontent.com/Johnshall/Shadowrocket-ADBlock-Rules-Forever/release/sr_top500_whitelist_ad.conf",
    "https://cdn.jsdelivr.net/gh/Johnshall/Shadowrocket-ADBlock-Rules-Forever@release/sr_top500_whitelist_ad.conf",
  ];
}

async function fetchFirstSuccessfulText(urls, label) {
  for (const url of urls) {
    let response;
    try {
      response = await fetch(url, {
        cf: {
          cacheEverything: true,
          cacheTtl: 21600,
        },
        headers: {
          "user-agent": "ziyi-proxy-subscription-worker",
        },
      });
    } catch (error) {
      console.error(`Rule mirror fetch threw for ${label}: ${url}`, error);
      continue;
    }

    if (!response.ok) {
      continue;
    }

    return {
      text: await response.text(),
      headers: response.headers,
    };
  }

  return null;
}

async function fetchUpstreamRuleText(name) {
  return fetchFirstSuccessfulText(upstreamUrls(name), name);
}

async function fetchShadowrocketUpstreamText() {
  return fetchFirstSuccessfulText(shadowrocketUpstreamUrls(), "shadowrocket");
}

function ruleUnavailable() {
  return new Response("Upstream rule source unavailable", {
    status: 502,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function buildRuleResponse(text) {
  const headers = new Headers({
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "public, max-age=21600",
  });
  return new Response(text, {
    status: 200,
    headers,
  });
}

async function fetchRuleSet(name) {
  const upstream = await fetchUpstreamRuleText(name);
  if (!upstream) {
    return ruleUnavailable();
  }

  return buildRuleResponse(upstream.text);
}

function validateSubscriptionRecord(subscription) {
  if (!subscription || typeof subscription !== "object" || Array.isArray(subscription)) {
    throw new Error("Subscription record must be an object");
  }

  if (typeof subscription.content !== "string") {
    throw new Error("Subscription record content must be a string");
  }

  if (
    subscription.content_type !== undefined &&
    subscription.content_type !== null &&
    typeof subscription.content_type !== "string"
  ) {
    throw new Error("Subscription record content_type must be a string when present");
  }

  return subscription;
}

function normalizeShadowrocketPolicy(token) {
  switch (token.trim().toLowerCase()) {
    case "reject":
      return "reject";
    case "direct":
      return "direct";
    case "proxy":
      return "proxy";
    default:
      return null;
  }
}

function extractShadowrocketRuleSection(text) {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const section = [];
  let inRuleSection = false;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (/^\[[^\]]+\]$/.test(line)) {
      if (inRuleSection) {
        break;
      }
      inRuleSection = line.toLowerCase() === "[rule]";
      continue;
    }

    if (inRuleSection) {
      section.push(line);
    }
  }

  return section;
}

function splitShadowrocketRuleBuckets(text) {
  const buckets = {
    reject: [],
    direct: [],
    proxy: [],
  };

  for (const line of extractShadowrocketRuleSection(text)) {
    if (!line || line.startsWith("#")) {
      continue;
    }

    const parts = line.split(",").map((part) => part.trim()).filter(Boolean);
    if (parts.length < 2) {
      continue;
    }

    if (parts[0].toUpperCase() === "FINAL" || parts[0].toUpperCase() === "RULE-SET") {
      continue;
    }

    let bucket = null;
    let policyIndex = -1;
    for (let index = parts.length - 1; index >= 1; index -= 1) {
      bucket = normalizeShadowrocketPolicy(parts[index]);
      if (bucket) {
        policyIndex = index;
        break;
      }
    }

    if (!bucket || policyIndex <= 0) {
      continue;
    }

    buckets[bucket].push(parts.slice(0, policyIndex).join(","));
  }

  return buckets;
}

async function fetchShadowrocketRuleSet(name) {
  const upstream = await fetchShadowrocketUpstreamText();
  if (!upstream) {
    return ruleUnavailable();
  }

  const bucket = splitShadowrocketRuleBuckets(upstream.text)[name] ?? [];
  return buildRuleResponse(bucket.length ? `${bucket.join("\n")}\n` : "");
}

function renderShadowrocketModule(origin) {
  return [
    "[General]",
    "ipv6 = true",
    "bypass-system = true",
    "private-ip-answer = true",
    "skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.0/8,localhost,*.local",
    "",
    "[Rule]",
    `RULE-SET,${origin}/shadowrocket-rules/reject.list,REJECT`,
    `RULE-SET,${origin}/shadowrocket-rules/direct.list,DIRECT`,
    `RULE-SET,${origin}/shadowrocket-rules/proxy.list,PROXY`,
    "DOMAIN-SUFFIX,cn,DIRECT",
    "GEOIP,CN,DIRECT",
    "IP-CIDR,192.168.0.0/16,DIRECT",
    "IP-CIDR,10.0.0.0/8,DIRECT",
    "IP-CIDR,172.16.0.0/12,DIRECT",
    "IP-CIDR,127.0.0.0/8,DIRECT",
    "IP-CIDR,fe80::/10,DIRECT",
    "IP-CIDR,fc00::/7,DIRECT",
    "IP-CIDR,::1/128,DIRECT",
    "FINAL,PROXY",
    "",
  ].join("\n");
}

async function loadSubscription(env, token) {
  if (!env || !env.SUBSCRIPTIONS || typeof env.SUBSCRIPTIONS.get !== "function") {
    throw new Error("SUBSCRIPTIONS binding is missing or invalid");
  }

  const raw = await env.SUBSCRIPTIONS.get(`sub:${token}`);
  if (raw === null) {
    return null;
  }

  try {
    return validateSubscriptionRecord(JSON.parse(raw));
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error("Subscription record contains malformed JSON");
    }

    throw error;
  }
}

function subscriptionResponse(subscription) {
  const contentType =
    typeof subscription.content_type === "string" && subscription.content_type.trim()
      ? subscription.content_type
      : "text/plain; charset=utf-8";

  return new Response(subscription.content, {
    status: 200,
    headers: {
      "content-type": contentType,
      "cache-control": "no-store",
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (shadowrocketModulePath(url.pathname)) {
      return new Response(renderShadowrocketModule(url.origin), {
        status: 200,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "public, max-age=300",
        },
      });
    }

    const token = subscriptionPathToken(url.pathname);
    if (token) {
      try {
        const subscription = await loadSubscription(env, token);
        if (!subscription) {
          return notFound();
        }

        return subscriptionResponse(subscription);
      } catch (error) {
        console.error(
          `Failed to load subscription for token ${redactTokenForLog(token)}`,
          error,
        );
        return internalError();
      }
    }

    const ruleName = rulePathName(url.pathname);
    if (ruleName) {
      if (RULES[ruleName]) {
        return fetchRuleSet(ruleName);
      }
      return notFound();
    }

    const shadowrocketRuleName = shadowrocketRulePathName(url.pathname);
    if (shadowrocketRuleName) {
      if (SHADOWROCKET_RULE_BUCKETS.has(shadowrocketRuleName)) {
        return fetchShadowrocketRuleSet(shadowrocketRuleName);
      }
      return notFound();
    }

    return notFound();
  },
};
