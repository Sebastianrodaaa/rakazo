import dns from "node:dns/promises";
import http from "node:http";
import net from "node:net";
import type { Duplex } from "node:stream";
import { ipLiteral, isPublicIp } from "./address.js";

export class EgressDenied extends Error {
  constructor(target: string) {
    super(`egress target is not a public address: ${target}`);
    this.name = "EgressDenied";
  }
}

export type ResolveFn = (hostname: string) => Promise<string[]>;
export type ConnectFn = (ip: string, port: number) => Duplex | Promise<Duplex>;

export interface EgressProxyOptions {
  resolve?: ResolveFn;
  connect?: ConnectFn;
  maxConnections?: number;
  idleTimeoutMs?: number;
}

const DEFAULT_MAX_CONNECTIONS = 256;
const DEFAULT_IDLE_TIMEOUT_MS = 60_000;

const defaultResolve: ResolveFn = async (hostname) => {
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  return records.map((record) => record.address);
};

const defaultConnect: ConnectFn = (ip, port) =>
  new Promise((resolve, reject) => {
    const socket = net.connect({ host: ip, port });
    socket.once("connect", () => resolve(socket));
    socket.once("error", reject);
  });

function deny(reason: string): never {
  throw new EgressDenied(reason);
}

/**
 * Resolve a proxy target to a concrete IP that is safe to dial. Returns a
 * validated address, never the name, so the dial cannot be rebound between
 * resolution and connect (DNS rebinding/TOCTOU). Denies literal IPs in
 * non-public ranges and any name with even one non-public answer.
 */
export async function resolveTargetHost(
  host: string,
  resolve: ResolveFn = defaultResolve,
): Promise<string> {
  const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (bare === "") deny(host);
  const literal = ipLiteral(bare);
  if (literal) {
    if (!isPublicIp(literal)) deny(host);
    return literal;
  }
  // Reject names that merely look like IPs in non-standard encodings: they are
  // resolved below, and the resolved address is what gets classified.
  const addresses = await resolve(bare).catch(() => []);
  if (addresses.length === 0) deny(host);
  for (const address of addresses) {
    if (!isPublicIp(address)) deny(`${host} (${address})`);
  }
  return addresses[0]!;
}

function parseConnectTarget(authority: string): { host: string; port: number } {
  const input = authority.trim();
  const match = input.startsWith("[")
    ? /^(\[[^\]]+\]):(\d+)$/.exec(input)
    : /^([^:]+):(\d+)$/.exec(input);
  const port = match ? Number(match[2]) : Number.NaN;
  if (!match || !Number.isInteger(port) || port < 1 || port > 65535) deny(authority);
  return { host: match![1]!, port };
}

function idle(socket: Duplex, ms: number) {
  const maybe = socket as Duplex & { setTimeout?: (ms: number, cb?: () => void) => void };
  maybe.setTimeout?.(ms, () => socket.destroy());
}

function tunnel(upstream: Duplex, downstream: Duplex) {
  upstream.pipe(downstream);
  downstream.pipe(upstream);
  upstream.once("error", () => downstream.destroy());
  downstream.once("error", () => upstream.destroy());
}

const HOP_BY_HOP = new Set(["connection", "proxy-connection", "proxy-authorization", "keep-alive"]);

export function createEgressProxy(options: EgressProxyOptions = {}) {
  const resolve = options.resolve ?? defaultResolve;
  const connect = options.connect ?? defaultConnect;
  const maxConnections = options.maxConnections ?? DEFAULT_MAX_CONNECTIONS;
  const idleTimeoutMs = options.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS;
  let open = 0;

  const server = http.createServer();

  server.on("connection", (socket: net.Socket) => {
    open += 1;
    socket.once("close", () => {
      open -= 1;
    });
    if (open > maxConnections) socket.destroy();
  });

  server.on("connect", async (req: http.IncomingMessage, socket: net.Socket, head: Buffer) => {
    const fail = (status: number, message: string) => {
      socket.end(`HTTP/1.1 ${status} ${message}\r\nContent-Length: 0\r\n\r\n`);
    };
    let target: { host: string; port: number };
    try {
      target = parseConnectTarget(req.url ?? "");
      const ip = await resolveTargetHost(target.host, resolve);
      const upstream = await connect(ip, target.port);
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head?.length) upstream.write(head);
      idle(socket, idleTimeoutMs);
      idle(upstream, idleTimeoutMs);
      tunnel(upstream, socket);
    } catch (error) {
      if (error instanceof EgressDenied) {
        fail(403, "Forbidden");
      } else {
        fail(502, "Bad Gateway");
      }
      return;
    }
  });

  server.on("request", async (req: http.IncomingMessage, res: http.ServerResponse) => {
    const client = req.socket;
    try {
      const url = new URL(req.url ?? "");
      if (url.protocol !== "http:") deny(req.url ?? "");
      if (url.username || url.password) deny(req.url ?? "");
      const ip = await resolveTargetHost(url.hostname, resolve);
      const port = url.port ? Number(url.port) : 80;
      const upstream = await connect(ip, port);
      const head = [`${req.method} ${url.pathname}${url.search} HTTP/1.1`];
      let hostWritten = false;
      for (const [name, value] of Object.entries(req.headers)) {
        const lower = name.toLowerCase();
        if (HOP_BY_HOP.has(lower)) continue;
        if (lower === "host") hostWritten = true;
        for (const item of Array.isArray(value) ? value : [value ?? ""]) {
          head.push(`${name}: ${item}`);
        }
      }
      if (!hostWritten) head.push(`Host: ${url.host}`);
      head.push("Connection: close", "", "");
      upstream.write(head.join("\r\n"));
      req.pipe(upstream);
      // The upstream status line and headers pass through untouched; the raw
      // client socket is used because the response is relayed verbatim.
      upstream.pipe(client);
      idle(upstream, idleTimeoutMs);
      upstream.once("error", () => client.destroy());
    } catch (error) {
      const denied = error instanceof EgressDenied || error instanceof TypeError;
      res.writeHead(denied ? 403 : 502, { "Content-Length": "0", Connection: "close" });
      res.end();
    }
  });

  return server;
}
