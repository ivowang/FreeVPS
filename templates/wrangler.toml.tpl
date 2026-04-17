name = "${WORKER_NAME}"
main = "src/index.js"
compatibility_date = "2026-04-16"
workers_dev = false

[[kv_namespaces]]
binding = "SUBSCRIPTIONS"
id = "${KV_NAMESPACE_ID}"

[[routes]]
pattern = "${SUBSCRIPTION_HOST}"
custom_domain = true
