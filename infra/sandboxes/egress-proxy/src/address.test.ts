import { describe, expect, it } from "vitest";
import { ipLiteral, isPublicIp, parseIpv4, parseIpv6 } from "./address.js";
import { EgressDenied, resolveTargetHost } from "./proxy.js";

const blocked = [
  "0.0.0.0",
  "0.255.255.255",
  "10.0.0.1",
  "10.255.255.255",
  "100.64.0.1",
  "100.127.255.254",
  "127.0.0.1",
  "127.53.0.1",
  "169.254.169.254",
  "172.16.0.1",
  "172.31.255.255",
  "192.0.0.1",
  "192.0.0.255",
  "192.168.1.1",
  "198.18.0.1",
  "198.19.255.255",
  "224.0.0.1",
  "239.255.255.255",
  "240.0.0.1",
  "255.255.255.255",
];

const allowed = [
  "8.8.8.8",
  "1.1.1.1",
  "93.184.216.34",
  "100.63.255.255",
  "100.128.0.1",
  "172.15.0.1",
  "172.32.0.1",
  "192.0.1.1",
  "198.17.255.255",
  "198.20.0.1",
  "203.0.114.1",
  "223.255.255.255",
];

describe("isPublicIp IPv4", () => {
  it.each(blocked)("blocks %s", (ip) => {
    expect(isPublicIp(ip)).toBe(false);
  });
  it.each(allowed)("allows %s", (ip) => {
    expect(isPublicIp(ip)).toBe(true);
  });
});

describe("isPublicIp IPv6", () => {
  it.each([
    "::",
    "::1",
    "fc00::1",
    "fd00::1",
    "fe80::1",
    "febf::ffff",
    "ff02::1",
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "::ffff:a9fe:a9fe",
    "::ffff:7f00:1",
    "::ffff:e000:1",
    "::7f00:1",
    "::a00:1",
    "::ffff:c0a8:101",
  ])("blocks %s", (ip) => {
    expect(isPublicIp(ip)).toBe(false);
  });
  it.each([
    "2606:4700:4700::1111",
    "2001:4860:4860::8888",
    "::ffff:8.8.8.8",
    "::ffff:808:808",
    "fb00::1",
    "fe70::1",
    "::8.8.8.8",
  ])("allows %s", (ip) => {
    expect(isPublicIp(ip)).toBe(true);
  });
});

describe("literal parsing", () => {
  it("rejects non-standard IPv4 encodings", () => {
    expect(parseIpv4("0x7f.1")).toBeNull();
    expect(parseIpv4("2130706433")).toBeNull();
    expect(parseIpv4("0177.0.0.1")).toBeNull();
    expect(parseIpv4("127.1")).toBeNull();
    expect(parseIpv4("256.1.1.1")).toBeNull();
  });
  it("detects literals including bracketed IPv6", () => {
    expect(ipLiteral("127.0.0.1")).toBe("127.0.0.1");
    expect(ipLiteral("[::1]")).toBe("::1");
    expect(ipLiteral("example.com")).toBeNull();
    expect(parseIpv6("[::1]")).not.toBeNull();
  });
});

describe("resolveTargetHost", () => {
  it("returns the validated IP, not the name", async () => {
    const ip = await resolveTargetHost("example.com", async () => ["93.184.216.34"]);
    expect(ip).toBe("93.184.216.34");
  });
  it("rejects literal private targets without resolving", async () => {
    const resolve = async () => {
      throw new Error("resolver must not run for literals");
    };
    for (const host of [
      "127.0.0.1",
      "10.0.0.1",
      "192.168.1.1",
      "172.16.5.4",
      "[::1]",
      "[fe80::1]",
    ]) {
      await expect(resolveTargetHost(host, resolve)).rejects.toBeInstanceOf(EgressDenied);
    }
  });
  it("rejects a name resolving to a private address", async () => {
    await expect(resolveTargetHost("localhost", async () => ["127.0.0.1"])).rejects.toBeInstanceOf(
      EgressDenied,
    );
    await expect(
      resolveTargetHost("host.docker.internal", async () => ["192.168.65.254"]),
    ).rejects.toBeInstanceOf(EgressDenied);
    await expect(resolveTargetHost("svc.local", async () => ["::1"])).rejects.toBeInstanceOf(
      EgressDenied,
    );
  });
  it("rejects a mixed public+private answer", async () => {
    await expect(
      resolveTargetHost("sneaky.example.com", async () => ["93.184.216.34", "10.0.0.7"]),
    ).rejects.toBeInstanceOf(EgressDenied);
  });
  it("rejects odd IP encodings once the resolver normalizes them", async () => {
    // getaddrinfo resolves forms like these to canonical addresses; the
    // resolved result is what gets classified.
    for (const host of ["2130706433", "0x7f.1", "0177.0.0.1", "127.1"]) {
      await expect(resolveTargetHost(host, async () => ["127.0.0.1"])).rejects.toBeInstanceOf(
        EgressDenied,
      );
    }
  });
  it("rejects empty and failing resolutions", async () => {
    await expect(resolveTargetHost("nx.example.com", async () => [])).rejects.toBeInstanceOf(
      EgressDenied,
    );
    await expect(
      resolveTargetHost("nx.example.com", async () => {
        throw new Error("ENOTFOUND");
      }),
    ).rejects.toBeInstanceOf(EgressDenied);
  });
});
