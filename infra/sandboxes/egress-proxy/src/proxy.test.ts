import type { AddressInfo } from "node:net";
import net from "node:net";
import { Duplex, PassThrough } from "node:stream";
import { afterEach, describe, expect, it } from "vitest";
import { createEgressProxy } from "./proxy.js";

let server: ReturnType<typeof createEgressProxy> | undefined;

afterEach(async () => {
  if (!server) return;
  await new Promise((resolve) => server!.close(resolve));
  server = undefined;
});

async function start(options: Parameters<typeof createEgressProxy>[0]) {
  server = createEgressProxy(options);
  await new Promise<void>((resolve) => server!.listen(0, "127.0.0.1", resolve));
  return (server!.address() as AddressInfo).port;
}

function exchange(port: number, request: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1");
    let buffer = "";
    socket.on("data", (chunk) => {
      buffer += chunk.toString();
      if (buffer.includes("\r\n\r\n")) {
        resolve(buffer);
        socket.destroy();
      }
    });
    socket.on("error", reject);
    socket.on("connect", () => socket.write(request));
    setTimeout(() => {
      resolve(buffer);
      socket.destroy();
    }, 2_000);
  });
}

describe("egress proxy", () => {
  it("CONNECTs to the validated IP and reports 200", async () => {
    const calls: Array<{ ip: string; port: number }> = [];
    const port = await start({
      resolve: async () => ["93.184.216.34"],
      connect: (ip, targetPort) => {
        calls.push({ ip, port: targetPort });
        return new PassThrough();
      },
    });
    const response = await exchange(
      port,
      "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
    );
    expect(response).toMatch(/^HTTP\/1\.1 200/);
    expect(calls).toEqual([{ ip: "93.184.216.34", port: 443 }]);
  });

  it.each([
    "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n",
    "CONNECT 10.0.0.1:22 HTTP/1.1\r\n\r\n",
    "CONNECT 192.168.1.1:80 HTTP/1.1\r\n\r\n",
    "CONNECT [::1]:443 HTTP/1.1\r\n\r\n",
    "CONNECT example.com:0 HTTP/1.1\r\n\r\n",
    "CONNECT example.com HTTP/1.1\r\n\r\n",
  ])("refuses %s", async (request) => {
    const connect = () => {
      throw new Error("must not dial");
    };
    const port = await start({ connect });
    const response = await exchange(port, request);
    expect(response).toMatch(/^HTTP\/1\.1 403/);
  });

  it("refuses a CONNECT name that resolves private", async () => {
    const port = await start({
      resolve: async () => ["192.168.65.254"],
      connect: () => {
        throw new Error("must not dial");
      },
    });
    const response = await exchange(port, "CONNECT host.docker.internal:443 HTTP/1.1\r\n\r\n");
    expect(response).toMatch(/^HTTP\/1\.1 403/);
  });

  it("forwards plain HTTP to the validated IP on the URL port", async () => {
    const calls: Array<{ ip: string; port: number }> = [];
    const port = await start({
      resolve: async () => ["93.184.216.34"],
      connect: (ip, targetPort) => {
        calls.push({ ip, port: targetPort });
        const upstream = new Duplex({
          write(_chunk, _encoding, callback) {
            callback();
          },
          read() {},
        });
        setImmediate(() => {
          upstream.push("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
          upstream.push(null);
        });
        return upstream;
      },
    });
    const response = await exchange(
      port,
      "GET http://example.com:8080/path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    expect(calls).toEqual([{ ip: "93.184.216.34", port: 8080 }]);
    expect(response).toMatch(/^HTTP\/1\.1 200/);
    expect(response).toContain("ok");
  });

  it.each([
    "GET http://127.0.0.1/admin HTTP/1.1\r\nHost: x\r\n\r\n",
    "GET http://0x7f.1/ HTTP/1.1\r\nHost: x\r\n\r\n",
    "GET http://2130706433/ HTTP/1.1\r\nHost: x\r\n\r\n",
    "GET http://user@10.0.0.1/ HTTP/1.1\r\nHost: x\r\n\r\n",
    "GET http://[::1]/ HTTP/1.1\r\nHost: x\r\n\r\n",
    "GET https://example.com/ HTTP/1.1\r\nHost: x\r\n\r\n",
  ])("refuses %s", async (request) => {
    const port = await start({
      connect: () => {
        throw new Error("must not dial");
      },
    });
    const response = await exchange(port, request);
    expect(response).toMatch(/^HTTP\/1\.1 403/);
  });
});
