import { createEgressProxy } from "./proxy.js";

// Forward proxy for bot computers. Each bot sits on an internal Docker network
// with no egress; this is the only way out, and it only dials globally
// routable addresses so the host, the LAN and sibling containers stay
// unreachable. It must never be published on the host or joined to the app
// networks — anyone who can reach it gets free egress.

const port = Number(process.env.EGRESS_PROXY_PORT ?? 3128);
const server = createEgressProxy({
  maxConnections: Number(process.env.EGRESS_MAX_CONNECTIONS ?? 256),
  idleTimeoutMs: Number(process.env.EGRESS_IDLE_TIMEOUT_MS ?? 60_000),
});

server.listen(port, () => {
  console.log(`egress proxy listening on :${port}`);
});

for (const signal of ["SIGTERM", "SIGINT"] as const) {
  process.once(signal, () => {
    server.close(() => process.exit(0));
  });
}
