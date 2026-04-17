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

function upstreamUrls(name) {
  return [
    `https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/${name}.txt`,
    `https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/${name}.txt`,
  ];
}

async function fetchUpstreamRuleText(name) {
  for (const url of upstreamUrls(name)) {
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
      console.error(`Rule mirror fetch threw for ${name}: ${url}`, error);
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

function unwrapPayloadEntries(text) {
  const normalized = text.replace(/\r\n/g, "\n");
  return normalized
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .filter((line) => line !== "payload:")
    .map((line) => line.replace(/^- /, ""))
    .map((line) => {
      const match = line.match(/^(['"])(.*)\1$/);
      return match ? match[2] : line;
    });
}

function convertPayloadYamlToShadowrocketList(text, behavior) {
  const entries = unwrapPayloadEntries(text);
  if (behavior === "ipcidr") {
    return `${entries.map((entry) => `IP-CIDR,${entry},no-resolve`).join("\n")}\n`;
  }

  return `${entries.join("\n")}\n`;
}

async function fetchShadowrocketRuleSet(name) {
  const upstream = await fetchUpstreamRuleText(name);
  if (!upstream) {
    return ruleUnavailable();
  }

  return buildRuleResponse(
    convertPayloadYamlToShadowrocketList(upstream.text, RULES[name].behavior),
  );
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
      if (RULES[shadowrocketRuleName]) {
        return fetchShadowrocketRuleSet(shadowrocketRuleName);
      }
      return notFound();
    }

    return notFound();
  },
};
