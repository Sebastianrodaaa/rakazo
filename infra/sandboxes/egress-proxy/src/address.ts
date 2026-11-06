// Address classification for the bot egress proxy. A target is allowed only
// when every address it resolves to is a globally routable unicast address.
// Anything private, loopback, link-local, multicast or reserved is denied so
// bot computers cannot reach the host, the LAN or sibling containers.

export function parseIpv4(host: string): number[] | null {
  // Strict dotted-quad only. Non-decimal encodings (0x7f.1, 2130706433,
  // 0177.0.0.1) must not parse here — they either arrive already normalized
  // by the URL/getaddrinfo layer or are handled as DNS names and denied on
  // the resolved address.
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return null;
  const parts = host.split(".").map(Number);
  return parts.every((part) => part <= 255) ? parts : null;
}

export function parseIpv6(host: string): number[] | null {
  const input = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (!input.includes(":")) return null;
  const halves = input.split("::");
  if (halves.length > 2) return null;
  const parseGroups = (side: string): number[] | null => {
    if (side === "") return [];
    const tokens = side.split(":");
    const groups: number[] = [];
    for (const [index, token] of tokens.entries()) {
      const isLast = index === tokens.length - 1;
      const embedded = isLast && token.includes(".") ? parseIpv4(token) : null;
      if (embedded) {
        groups.push((embedded[0]! << 8) | embedded[1]!, (embedded[2]! << 8) | embedded[3]!);
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(token)) return null;
      groups.push(Number.parseInt(token, 16));
    }
    return groups;
  };
  const head = parseGroups(halves[0]!);
  if (!head) return null;
  const tail = halves.length === 2 ? parseGroups(halves[1]!) : [];
  if (!tail) return null;
  const total = head.length + tail.length;
  if (halves.length === 2 ? total > 7 : total !== 8) return null;
  const groups =
    halves.length === 2 ? [...head, ...Array<number>(8 - total).fill(0), ...tail] : head;
  const bytes: number[] = [];
  for (const group of groups) {
    bytes.push(group >> 8, group & 0xff);
  }
  return bytes;
}

function isPublicV4(b: number[]): boolean {
  const [a, sec, c] = b as [number, number, number, number];
  if (a === 0) return false; // 0.0.0.0/8 "this host"
  if (a === 10) return false; // RFC 1918
  if (a === 100 && (sec & 0xc0) === 64) return false; // CGNAT 100.64/10
  if (a === 127) return false; // loopback
  if (a === 169 && sec === 254) return false; // link-local
  if (a === 172 && (sec & 0xf0) === 16) return false; // RFC 1918
  if (a === 192 && sec === 0 && c === 0) return false; // IETF protocol assignments
  if (a === 192 && sec === 168) return false; // RFC 1918
  if (a === 198 && (sec & 0xfe) === 18) return false; // benchmark 198.18/15
  if (a >= 224) return false; // multicast 224/4 and reserved 240/4
  return true;
}

function isPublicV6(b: number[]): boolean {
  const headZero = b.slice(0, 10).every((byte) => byte === 0);
  if (headZero && b[10] === 0xff && b[11] === 0xff) {
    // IPv4-mapped (::ffff:a.b.c.d): classify the embedded IPv4 address.
    return isPublicV4(b.slice(12));
  }
  if (b.slice(0, 12).every((byte) => byte === 0)) {
    // ::, ::1 and deprecated IPv4-compat (::a.b.c.d): classify as IPv4 so
    // ::7f00:1 is denied like 127.0.0.1, and ::/::1 are denied as 0.0.0.0.
    return isPublicV4(b.slice(12));
  }
  const [a, sec] = b as [number, number, ...number[]];
  if ((a & 0xfe) === 0xfc) return false; // ULA fc00::/7
  if (a === 0xfe && (sec & 0xc0) === 0x80) return false; // link-local fe80::/10
  if (a === 0xff) return false; // multicast ff00::/8
  return true;
}

/** True only when `ip` is an IP literal in a globally routable unicast range. */
export function isPublicIp(ip: string): boolean {
  const v4 = parseIpv4(ip);
  if (v4) return isPublicV4(v4);
  const v6 = parseIpv6(ip);
  if (v6) return isPublicV6(v6);
  return false;
}

/** Non-null when `host` is a literal IP (v4 or [bracketed] v6) rather than a name. */
export function ipLiteral(host: string): string | null {
  const bare = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (parseIpv4(bare)) return bare;
  if (parseIpv6(bare)) return bare;
  return null;
}
