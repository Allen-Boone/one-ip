// ============================================================================
// one-ip-worker.js —— 单文件版 IP 与网络诊断工具箱（Cloudflare Worker）
//
// 功能参考开源项目 zhihui-hu/one-ip 的公开行为重新实现。
// 本文件为全新编写的单文件版本：前端 HTML/CSS/JS 直接内嵌，
// 不需要任何构建步骤，不依赖 ASSETS / KV / Rate Limiting 等绑定，
// 直接粘贴到 Cloudflare 控制台 Worker 编辑器点 Deploy 即可上线。
//
// 修复的已知问题（相对原部署）：
//  1. /api/dns/lookup 不再被前置拦截，真正可用（Cloudflare / Google / Quad9 DoH）。
//  2. 429 文案修正为“请求过于频繁，请一分钟后重试”。
//  3. 前端探测不再要求跨域可读响应：图标 <img> 加载 + fetch no-cors 双信号，
//     失败重试一次，超时放宽到 8 秒，计数更稳定；页面上写明探测口径。
//  4. 不依赖 env.ASSETS，控制台预览不再报错；不含任何登录/鉴权逻辑，
//     不含 LOCAL_DEV 回环代理；限流用内存 Map 实现。
// ============================================================================

// ---------------- 基础工具 ----------------

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function json(data, status = 200, extraHeaders) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...(extraHeaders || {}),
    },
  });
}

function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || null;
}

// ---- IP 地址校验（不使用 node:net，用正则实现）----

const IPV4_RE =
  /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)$/;
const IPV6_RE =
  /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

function ipVersion(value) {
  if (typeof value !== "string") return 0;
  if (IPV4_RE.test(value)) return 4;
  if (IPV6_RE.test(value)) return 6;
  return 0;
}

// 只接受公网地址：拒绝私有、回环、保留、文档、组播等地址。
function publicIp(value) {
  const v = ipVersion(value);
  if (!v || value.includes("%"))
    throw new HttpError(400, "请输入有效的公网 IPv4 或 IPv6 地址");
  if (v === 6) {
    let ip = value.toLowerCase();
    // IPv4 映射地址 ::ffff:a.b.c.d 按 IPv4 校验
    const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return publicIp(mapped[1]);
    // 只接受 2000::/3 全球单播；排除 6to4、文档、Teredo、特殊用途段
    if (
      !/^[23]/.test(ip) ||
      ip.startsWith("2002:") ||
      /^2001:(db8|2|10|20):/.test(ip) ||
      ip.startsWith("2001:0:") ||
      ip.startsWith("2001::")
    )
      throw new HttpError(400, "不支持私有、回环或保留地址");
    return ip;
  }
  const [a, b, c] = value.split(".").map(Number);
  if (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    a >= 224 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 &&
      (b === 168 ||
        (b === 0 && (c === 0 || c === 2)) ||
        (b === 88 && c === 99))) ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113)
  )
    throw new HttpError(400, "不支持私有、回环或保留地址");
  return value;
}

// 把域名转成 ASCII（Punycode），非法域名返回 null。
function toASCII(host) {
  try {
    return new URL("https://" + host).hostname;
  } catch {
    return null;
  }
}

// 校验“域名或公网 IP”输入，返回规范化后的域名或 IP。
function target(value) {
  if (typeof value !== "string" || !value || value.length > 253)
    throw new HttpError(400, "请输入有效的域名或 IP");
  const host = value.trim().replace(/\.$/, "").toLowerCase();
  if (ipVersion(host)) return publicIp(host);
  if (/[\s/:@%*?#\\]/.test(host))
    throw new HttpError(400, "请输入公网域名，不包含协议、路径或端口");
  const ascii = toASCII(host);
  if (
    !ascii ||
    ascii.length > 253 ||
    !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9](?:[a-z0-9-]{0,57}[a-z0-9])?)$/.test(
      ascii,
    ) ||
    /\.(localhost|local|internal|test|invalid|example)$/.test(ascii)
  )
    throw new HttpError(400, "请输入公网域名，不包含协议、路径或端口");
  return ascii;
}

// IPv6 展开为 8 组 4 位十六进制（供 RDAP 前缀匹配用）。
function expandIPv6(ip) {
  const [head, tail] = ip.split("::");
  const h = head ? head.split(":") : [];
  const t = tail !== undefined && tail !== "" ? tail.split(":") : [];
  const missing = 8 - h.length - t.length;
  return [...h, ...Array(missing).fill("0"), ...t].map((p) =>
    p.padStart(4, "0"),
  );
}

function ipToBigInt(ip) {
  if (ipVersion(ip) === 4)
    return ip.split(".").reduce((n, o) => (n << 8n) + BigInt(o), 0n);
  return expandIPv6(ip).reduce((n, p) => (n << 16n) + BigInt("0x" + p), 0n);
}

// ---- 上游请求（带超时与大小上限，失败只返回友好中文文案）----

async function boundedText(response, maxBytes = 2000000, errorStatus = 502) {
  const reader = response.body?.getReader();
  if (!reader) throw new HttpError(errorStatus, "上游返回内容为空");
  let size = 0;
  const chunks = [];
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes)
        throw new HttpError(errorStatus === 400 ? 413 : errorStatus, "上游内容过大");
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return new TextDecoder().decode(bytes);
}

async function boundedJson(response, maxBytes = 2000000, errorStatus = 502) {
  const text = await boundedText(response, maxBytes, errorStatus);
  try {
    return JSON.parse(text);
  } catch {
    throw new HttpError(errorStatus, "上游内容不是有效 JSON");
  }
}

async function upstream(url, init = {}, maxBytes = 2000000, mode = "json") {
  let response;
  try {
    response = await fetch(url, {
      ...init,
      signal: init.signal
        ? AbortSignal.any([init.signal, AbortSignal.timeout(10000)])
        : AbortSignal.timeout(10000),
    });
  } catch {
    throw new HttpError(502, "外部数据源连接失败或超时");
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new HttpError(
      response.status === 429 ? 429 : 502,
      response.status === 429
        ? "外部数据源限流，请稍后重试"
        : "外部数据源暂不可用（" + response.status + "）",
    );
  }
  return mode === "text"
    ? boundedText(response, maxBytes)
    : boundedJson(response, maxBytes);
}

async function inputJson(request) {
  if (!request.headers.get("Content-Type")?.includes("application/json"))
    throw new HttpError(415, "需要 application/json");
  const value = await boundedJson(request, 4096, 400);
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new HttpError(400, "需要 JSON 对象");
  return value;
}

// ---- 内存缓存（替代 Cache API；实例回收后失效，仅作加速用）----

const MEM_CACHE = new Map();
async function cached(key, ttlMs, fn, validate) {
  const now = Date.now();
  const hit = MEM_CACHE.get(key);
  if (hit && hit.expiresAt > now) return hit.value;
  const value = await fn();
  if (!validate || validate(value)) {
    if (MEM_CACHE.size > 1000) {
      for (const [k, v] of MEM_CACHE) if (v.expiresAt <= now) MEM_CACHE.delete(k);
    }
    MEM_CACHE.set(key, { value, expiresAt: now + ttlMs });
  }
  return value;
}

// ---- 内存限流（替代 Rate Limiting 绑定；尽力而为）----
// GET 每 IP 每分钟 180 次；POST 每 IP 每分钟 10 次；图标走 GET 桶。
const LIMITS = new Map();
function checkLimit(key, limit, windowMs = 60000) {
  const now = Date.now();
  if (LIMITS.size > 10000) {
    for (const [k, v] of LIMITS) if (v.resetAt <= now) LIMITS.delete(k);
  }
  const rec = LIMITS.get(key);
  if (!rec || rec.resetAt <= now) {
    LIMITS.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }
  if (rec.count >= limit) return false;
  rec.count += 1;
  return true;
}

// ---------------- 地理归属 ----------------

function cfGeo(request) {
  const cf = request.cf ?? {};
  return {
    ip: clientIp(request) ?? "",
    country: cf.country,
    country_code: cf.country,
    region: cf.region,
    city: cf.city,
    isp: cf.asOrganization,
    asn: cf.asn,
    latitude: cf.latitude ? Number(cf.latitude) : undefined,
    longitude: cf.longitude ? Number(cf.longitude) : undefined,
    timezone: cf.timezone,
    source: "Cloudflare request.cf",
  };
}

async function geoIp(ip) {
  ip = publicIp(ip);
  const data = await upstream("https://ipwho.is/" + encodeURIComponent(ip));
  if (!data?.success || data.ip !== ip)
    throw new Error("IP 归属地数据源未返回有效结果");
  return {
    ip: data.ip,
    country: data.country,
    country_code: data.country_code,
    region: data.region,
    city: data.city,
    isp: data.connection?.isp,
    asn: data.connection?.asn,
    latitude: data.latitude,
    longitude: data.longitude,
    timezone: data.timezone?.id,
    source: "ipwho.is",
  };
}

async function secondaryGeo(ip) {
  ip = publicIp(ip);
  const data = await upstream(
    "https://api.ip.sb/geoip/" + encodeURIComponent(ip),
  );
  if (!data?.ip || data.ip !== ip)
    throw new Error("第二归属地数据源未返回结果");
  return {
    ip: data.ip,
    country: data.country,
    country_code: data.country_code,
    city: data.city,
    isp: data.isp,
    asn: data.asn,
    latitude: data.latitude,
    longitude: data.longitude,
    source: "ip.sb",
  };
}

// ---------------- IP 信誉 ----------------
// 信誉数据来自 Net.Coffee；取不到访客 IP 时直接 503，不编造示例数据。

async function ipHealth(request) {
  const ip = clientIp(request);
  if (!ip) throw new HttpError(503, "无法获取当前 IP，请稍后再试");
  const data = await upstream(
    "https://ip.net.coffee/api/ip/lookup/" + encodeURIComponent(ip),
    {},
    2000000,
    "json",
  );
  const score =
    typeof data?.score === "number"
      ? data.score
      : typeof data?.risk_score === "number"
        ? data.risk_score
        : typeof data?.abuse_score === "number"
          ? data.abuse_score
          : typeof data?.fraud_score === "number"
            ? data.fraud_score
            : null;
  return {
    ip,
    score,
    risk: data?.risk ?? data?.level ?? null,
    isHosting: data?.hosting ?? data?.is_hosting ?? null,
    isProxy: data?.proxy ?? data?.is_proxy ?? null,
    isVpn: data?.vpn ?? data?.is_vpn ?? null,
    isTor: data?.tor ?? data?.is_tor ?? null,
    country: data?.country ?? data?.country_code ?? null,
    isp: data?.isp ?? null,
    asn: data?.asn ?? null,
    raw: data,
    source: "Net.Coffee",
    checkedAt: new Date().toISOString(),
  };
}

// ---------------- IP 类型（机房 / 移动 / 代理）----------------
// 数据来自 ip-api.com；上游限流或失败时返回 available:false，不抛错。

let ipApiRetryAfter = 0;

async function ipType(value, origin) {
  const ip = publicIp(value);
  const cacheKey = "iptype:" + ip;
  const hit = MEM_CACHE.get(cacheKey);
  if (hit && hit.expiresAt > Date.now()) return hit.value;
  const result = await ipTypeFresh(ip);
  MEM_CACHE.set(cacheKey, { value: result, expiresAt: Date.now() + 3600000 });
  return result;
}

async function ipTypeFresh(ip) {
  if (Date.now() < ipApiRetryAfter) return { available: false };
  try {
    const response = await fetch(
      "http://ip-api.com/json/" +
        encodeURIComponent(ip) +
        "?fields=status,query,hosting,mobile,proxy",
      { redirect: "manual", signal: AbortSignal.timeout(5000) },
    );
    if (response.status === 429 || response.headers.get("X-Rl") === "0") {
      const ttl = Number(response.headers.get("X-Ttl"));
      ipApiRetryAfter =
        Date.now() + (Number.isFinite(ttl) && ttl > 0 ? ttl : 60) * 1000;
    }
    if (!response.ok) {
      await response.body?.cancel();
      return { available: false };
    }
    const data = await boundedJson(response, 4096);
    if (
      data.status !== "success" ||
      ![data.hosting, data.mobile, data.proxy].every(
        (flag) => typeof flag === "boolean",
      ) ||
      data.query !== ip
    )
      return { available: false };
    return {
      available: true,
      hosting: data.hosting,
      mobile: data.mobile,
      proxy: data.proxy,
    };
  } catch {
    return { available: false };
  }
}

// ---------------- 网络拓扑（RIPE RIS / RIPEstat）----------------

const TIER1_ASNS = new Set([
  "174", "1299", "2914", "3257", "3356", "5511",
  "6453", "6461", "6762", "6939", "7018",
]);

async function ripe(name, params) {
  const response = await fetch(
    "https://stat.ripe.net/data/" + name + "/data.json?" + new URLSearchParams(params),
    { signal: AbortSignal.timeout(4000) },
  );
  if (!response.ok) throw new Error("RIPE 暂不可用");
  const result = await boundedJson(response);
  if (result.status !== "ok" || !result.data) throw new Error("RIPE 暂不可用");
  return result.data;
}

function normalizeAsn(value) {
  const m = String(value ?? "").trim().match(/^(?:AS)?(\d+)$/i);
  return m ? m[1] : undefined;
}

function parseBgpPath(path) {
  if (!Array.isArray(path)) return [];
  const list = path.map(normalizeAsn).filter(Boolean);
  return list.filter((asn, i) => i === 0 || asn !== list[i - 1]);
}

function bump(map, key, amount = 1) {
  map.set(key, (map.get(key) ?? 0) + amount);
}

function byCountThenAsn([aAsn, aCount], [bAsn, bCount]) {
  return (
    bCount - aCount ||
    aAsn.localeCompare(bAsn, undefined, { numeric: true })
  );
}

function shareOf(count, total) {
  return Math.round((count / total) * 1000) / 10;
}

function topItems(counts, total, limit) {
  return [...counts.entries()]
    .sort(byCountThenAsn)
    .slice(0, limit)
    .map(([asn, count]) => ({
      asn,
      count,
      share: shareOf(count, total),
      tier1: TIER1_ASNS.has(asn),
    }));
}

function buildTopology(state, prefix, announcingAsns) {
  const records = Array.isArray(state?.bgp_state) ? state.bgp_state : [];
  const exact = records.filter((r) => r?.target_prefix === prefix);
  const candidates = exact.length ? exact : records;
  const paths = candidates
    .map((r) => parseBgpPath(r?.path))
    .filter((p) => p.length > 0);
  if (!paths.length) return undefined;
  const knownOrigins = new Set(announcingAsns);
  const matching = knownOrigins.size
    ? paths.filter((p) => knownOrigins.has(p[p.length - 1]))
    : [];
  const usable = matching.length ? matching : paths;
  const origins = new Map();
  const direct = new Map();
  const directEdges = new Map();
  const secondary = new Map();
  const secondaryEdges = new Map();
  const secondaryVia = new Map();
  for (const path of usable) {
    const origin = path[path.length - 1];
    bump(origins, origin);
    if (path.length < 2) continue;
    const directAsn = path[path.length - 2];
    if (directAsn === origin) continue;
    bump(direct, directAsn);
    bump(directEdges, origin + "|" + directAsn);
    if (path.length < 3) continue;
    const secondAsn = path[path.length - 3];
    if (secondAsn === directAsn || secondAsn === origin) continue;
    bump(secondary, secondAsn);
    bump(secondaryEdges, directAsn + "|" + secondAsn);
    if (!secondaryVia.has(secondAsn)) secondaryVia.set(secondAsn, new Map());
    bump(secondaryVia.get(secondAsn), directAsn);
  }
  if (!direct.size) return undefined;
  const total = usable.length;
  const originItems = topItems(origins, total, 4);
  const directItems = topItems(direct, total, 6);
  const originSet = new Set(originItems.map((x) => x.asn));
  const directSet = new Set(directItems.map((x) => x.asn));
  const visibleSecondary = new Map();
  for (const [key, count] of secondaryEdges) {
    const [dAsn, sAsn] = key.split("|");
    if (!directSet.has(dAsn)) continue;
    bump(visibleSecondary, sAsn, count);
  }
  const secondaryItems = topItems(visibleSecondary, total, 8).map((item) => ({
    ...item,
    via: [...(secondaryVia.get(item.asn)?.entries() ?? [])]
      .filter(([dAsn]) => directSet.has(dAsn))
      .sort(byCountThenAsn)
      .map(([dAsn]) => dAsn)
      .slice(0, 3),
  }));
  const secondarySet = new Set(secondaryItems.map((x) => x.asn));
  const edges = [...directEdges.entries()]
    .map(([key, count]) => {
      const [origin, directAsn] = key.split("|");
      return { origin, direct: directAsn, count, share: shareOf(count, total) };
    })
    .filter((e) => originSet.has(e.origin) && directSet.has(e.direct));
  const secondaryEdgeItems = [...secondaryEdges.entries()]
    .map(([key, count]) => {
      const [dAsn, sAsn] = key.split("|");
      return { direct: dAsn, secondary: sAsn, count, share: shareOf(count, total) };
    })
    .filter((e) => directSet.has(e.direct) && secondarySet.has(e.secondary));
  return {
    observedPaths: total,
    queryTime: state.query_time,
    origins: originItems,
    direct: directItems,
    secondary: secondaryItems,
    edges,
    secondaryEdges: secondaryEdgeItems,
    lookupAsns: [
      ...new Set([
        ...originItems.map((x) => x.asn),
        ...directItems.map((x) => x.asn),
        ...secondaryItems.map((x) => x.asn),
      ]),
    ].slice(0, 20),
  };
}

async function holderFor(asn) {
  try {
    const data = await ripe("as-overview", { resource: "AS" + asn });
    const holder = typeof data?.holder === "string" ? data.holder.trim() : "";
    return holder || undefined;
  } catch {
    return undefined;
  }
}

async function addHolders(topology) {
  const holders = await Promise.all(
    topology.lookupAsns.map(async (asn) => [asn, await holderFor(asn)]),
  );
  const names = new Map(holders);
  const decorate = (item) =>
    names.get(item.asn) ? { ...item, name: names.get(item.asn) } : item;
  const out = { ...topology };
  delete out.lookupAsns;
  return {
    ...out,
    origins: topology.origins.map(decorate),
    direct: topology.direct.map(decorate),
    secondary: topology.secondary.map(decorate),
  };
}

async function ipNetwork(ip) {
  const [network, reverse, state] = await Promise.allSettled([
    ripe("network-info", { resource: ip }),
    ripe("reverse-dns-ip", { resource: ip }),
    ripe("bgp-state", { resource: ip }),
  ]);
  const route = network.status === "fulfilled" ? network.value : undefined;
  const dns = reverse.status === "fulfilled" ? reverse.value : undefined;
  const asns = Array.isArray(route?.asns)
    ? route.asns.map(normalizeAsn).filter(Boolean)
    : [];
  const rawTopology =
    route?.prefix && state.status === "fulfilled"
      ? buildTopology(state.value, route.prefix, asns)
      : undefined;
  const validationsPromise = route?.prefix
    ? Promise.all(
        asns.map(async (asn) => {
          try {
            const data = await ripe("rpki-validation", {
              resource: asn,
              prefix: route.prefix,
            });
            return { asn, status: data.status, description: data.description };
          } catch {
            return { asn, status: "unavailable" };
          }
        }),
      )
    : Promise.resolve([]);
  const topologyPromise = rawTopology
    ? addHolders(rawTopology)
    : Promise.resolve(undefined);
  const [validations, topology] = await Promise.all([
    validationsPromise,
    topologyPromise,
  ]);
  return {
    prefix: route?.prefix,
    asns,
    ptr: Array.isArray(dns?.result)
      ? dns.result.join(" / ")
      : dns?.result || undefined,
    routeAvailable: Boolean(route),
    ptrAvailable: Boolean(dns && !dns.error),
    validations,
    topology,
    source: "RIPE RIS / RIPEstat",
    checkedAt: new Date().toISOString(),
  };
}

// 轻量版：只取网段、ASN 与反向解析（供 /ip/<ip> 合并展示用）。
async function ripeBasic(ip) {
  const [network, reverse] = await Promise.allSettled([
    ripe("network-info", { resource: ip }),
    ripe("reverse-dns-ip", { resource: ip }),
  ]);
  const route = network.status === "fulfilled" ? network.value : undefined;
  const dns = reverse.status === "fulfilled" ? reverse.value : undefined;
  return {
    prefix: route?.prefix,
    asns: Array.isArray(route?.asns)
      ? route.asns.map(normalizeAsn).filter(Boolean)
      : [],
    ptr: Array.isArray(dns?.result)
      ? dns.result.join(" / ")
      : dns?.result || undefined,
  };
}

// ---------------- WHOIS / RDAP 注册信息 ----------------

function registrationTarget(query) {
  const raw = query.trim();
  if (/^AS\d+$/i.test(raw)) {
    const asn = Number(raw.slice(2));
    if (!Number.isSafeInteger(asn) || asn < 1 || asn > 4294967295)
      throw new HttpError(400, "无效的 AS 号");
    return "AS" + asn;
  }
  if (ipVersion(raw)) return publicIp(raw);
  let ascii;
  try {
    ascii = new URL("https://" + raw).hostname;
  } catch {
    throw new HttpError(400, "请输入有效的域名、IP 或 AS 号");
  }
  if (/[\s/@?#:]/.test(raw))
    throw new HttpError(400, "仅输入域名，不包含路径或协议");
  return target(ascii);
}

// IANA RDAP 引导文件很少变化，用内存缓存一天。
async function bootstrapJson(url, signal) {
  return cached("rdap-boot:" + url, 86400000, async () => {
    const data = await upstream(url, {
      signal,
      headers: { Accept: "application/json" },
    });
    if (!Array.isArray(data?.services))
      throw new HttpError(502, "注册信息数据源未返回有效结果");
    return data;
  });
}

function registrationServer(ip, services) {
  const bits = ipVersion(ip) === 4 ? 32 : 128;
  const value = ipToBigInt(ip);
  const matches = services
    .flatMap(([prefixes, urls]) =>
      prefixes.flatMap((prefix) => {
        const [address, length] = prefix.split("/");
        if (ipVersion(address) !== ipVersion(ip)) return [];
        const shift = BigInt(bits - Number(length));
        return value >> shift === ipToBigInt(address) >> shift
          ? [{ length: Number(length), urls }]
          : [];
      }),
    )
    .sort((a, b) => b.length - a.length);
  return matches[0]?.urls.find((u) => u.startsWith("https://"));
}

async function lookupRegistration(query) {
  const raw = registrationTarget(query);
  const signal = AbortSignal.timeout(10000);
  const options = {
    headers: { Accept: "application/rdap+json, application/json" },
    signal,
  };
  let path;
  let endpoint;
  if (/^AS\d+$/.test(raw)) {
    path = "autnum/" + raw.slice(2);
  } else if (ipVersion(raw)) {
    path = "ip/" + encodeURIComponent(raw);
  } else {
    const domain = raw;
    path = "domain/" + encodeURIComponent(domain);
    const bootstrap = await bootstrapJson(
      "https://data.iana.org/rdap/dns.json",
      AbortSignal.any([signal, AbortSignal.timeout(2000)]),
    );
    const urls = bootstrap.services.find(([suffixes]) =>
      suffixes.includes(domain.split(".").at(-1)),
    )?.[1];
    const base = urls?.find((u) => u.startsWith("https://"));
    if (!base)
      throw new HttpError(422, "该域名后缀暂无可用的 HTTPS RDAP 服务");
    endpoint = new URL(path, base.endsWith("/") ? base : base + "/").href;
  }
  let data;
  try {
    data = await upstream(endpoint ?? "https://rdap.org/" + path, {
      ...options,
      signal: ipVersion(raw)
        ? AbortSignal.any([signal, AbortSignal.timeout(4000)])
        : signal,
    });
  } catch (error) {
    if (!ipVersion(raw) || signal.aborted) throw error;
    const ip = publicIp(raw);
    const bootstrap = await bootstrapJson(
      "https://data.iana.org/rdap/ipv" + ipVersion(ip) + ".json",
      AbortSignal.any([signal, AbortSignal.timeout(2000)]),
    );
    const base = registrationServer(ip, bootstrap.services);
    if (!base) throw error;
    data = await upstream(new URL(path, base).href, options);
  }
  if (
    !data ||
    typeof data !== "object" ||
    Array.isArray(data) ||
    Object.hasOwn(data, "errorCode")
  )
    throw new HttpError(502, "注册信息数据源未返回有效结果");
  return { source: "RDAP · 注册局公开数据", query: raw, data };
}

// ---------------- 子域名查询（crt.sh）----------------

async function lookupSubdomains(value) {
  const domain = target(value);
  if (ipVersion(domain))
    throw new HttpError(400, "子域名查询请输入域名，不要输入 IP");
  const data = await upstream(
    "https://crt.sh/?q=%25." + encodeURIComponent(domain) + "&output=json",
    {},
    2000000,
    "json",
  );
  if (!Array.isArray(data))
    throw new HttpError(502, "子域名数据源未返回有效结果");
  const names = new Set();
  for (const item of data) {
    const raw = String(item?.name_value ?? "");
    for (const line of raw.split("\n")) {
      const name = line.trim().toLowerCase().replace(/^\*\./, "");
      if (name && name.endsWith("." + domain)) names.add(name);
    }
    if (names.size >= 200) break;
  }
  return {
    domain,
    count: names.size,
    subdomains: [...names].sort().slice(0, 100),
    truncated: names.size > 100,
    source: "crt.sh",
  };
}

// ---------------- DNS 查询（DNS over HTTPS）----------------
// 原部署的 /dns/lookup 被前置拦截导致永远 404；本版直接实现，不再拦截。

const DNS_TYPES = {
  A: 1, AAAA: 28, MX: 15, TXT: 16, NS: 2, CNAME: 5,
  SOA: 6, PTR: 12, SRV: 33, CAA: 257, HTTPS: 65,
};

const DOH_RESOLVERS = {
  cf: {
    name: "Cloudflare",
    url: "https://cloudflare-dns.com/dns-query",
  },
  google: {
    name: "Google",
    url: "https://dns.google/resolve",
  },
  quad9: {
    name: "Quad9",
    url: "https://dns.quad9.net:5053/dns-query",
  },
};

async function dnsLookup(domain, type = "A", resolver = "cf") {
  const host = target(domain);
  if (ipVersion(host) && type !== "PTR")
    throw new HttpError(400, "查 IP 的反向解析请用 PTR 类型");
  const t = String(type || "A").toUpperCase();
  if (!DNS_TYPES[t]) throw new HttpError(400, "不支持的 DNS 记录类型");
  const r = DOH_RESOLVERS[resolver] || DOH_RESOLVERS.cf;
  const url =
    r.url +
    "?name=" +
    encodeURIComponent(host) +
    "&type=" +
    DNS_TYPES[t];
  const data = await upstream(url, {
    headers: { Accept: "application/dns-json" },
  });
  return {
    domain: host,
    type: t,
    resolver: r.name,
    status: data?.Status ?? null,
    answers: Array.isArray(data?.Answer)
      ? data.Answer.map((a) => ({ name: a.name, type: a.type, ttl: a.TTL, data: a.data }))
      : [],
    authority: Array.isArray(data?.Authority) ? data.Authority.length : 0,
    comment: data?.Comment ?? null,
  };
}

// ---------------- CDN 识别（响应头特征）----------------

const CDN_SIGNATURES = [
  { test: (h) => h["cf-ray"], name: "Cloudflare" },
  { test: (h) => h["x-amz-cf-id"] || h["x-amz-cf-pop"], name: "CloudFront" },
  { test: (h) => /akamai/i.test(h.server || "") || h["x-akamai-transformed"], name: "Akamai" },
  { test: (h) => /cloudfront/i.test(h.server || "") || /cloudfront/i.test(h.via || ""), name: "CloudFront" },
  { test: (h) => /fastly/i.test(h.via || "") || h["x-fastly-request-id"], name: "Fastly" },
  { test: (h) => /gws|google/i.test(h.server || "") && h["x-goog-metageneration"], name: "Google Cloud" },
  { test: (h) => h["x-cache"] && /aliyun|alicdn/i.test(h["x-cache"] + (h.via || "")), name: "阿里云 CDN" },
  { test: (h) => /tencentyun|qcloud/i.test((h.server || "") + (h.via || "")), name: "腾讯云 CDN" },
  { test: (h) => h["x-svr"] || /upyun/i.test(h.server || ""), name: "又拍云" },
  { test: (h) => /cdn/i.test(h.server || ""), name: "CDN（未知厂商）" },
];

async function detectCdn(value) {
  const host = target(value);
  if (ipVersion(host)) {
    const basic = await ripeBasic(host);
    return {
      input: host,
      kind: "ip",
      cdn: null,
      provider: null,
      note: "输入为 IP 地址，无法从响应头判断 CDN；请用域名查询",
      prefix: basic.prefix,
      asns: basic.asns,
      ptr: basic.ptr,
    };
  }
  let headers = {};
  let status = null;
  try {
    const response = await fetch("https://" + host + "/", {
      method: "HEAD",
      redirect: "manual",
      signal: AbortSignal.timeout(6000),
    });
    status = response.status;
    response.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    await response.body?.cancel();
  } catch {
    throw new HttpError(502, "目标站点连接失败或超时，无法识别 CDN");
  }
  const hit = CDN_SIGNATURES.find((s) => {
    try {
      return s.test(headers);
    } catch {
      return false;
    }
  });
  return {
    input: host,
    kind: "domain",
    httpStatus: status,
    cdn: hit ? hit.name : null,
    provider: hit ? hit.name : "未检测到常见 CDN 特征",
    evidence: {
      server: headers.server || null,
      via: headers.via || null,
      cfRay: headers["cf-ray"] || null,
      cache: headers["x-cache"] || null,
    },
  };
}

// ---------------- 网站图标代理 ----------------

async function siteIcon(host) {
  const domain = target(host);
  const url =
    domain === "weixin.qq.com"
      ? "https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico"
      : "https://icons.duckduckgo.com/ip3/" + domain + ".ico";
  const response = await fetch(url, {
    redirect: "manual",
    signal: AbortSignal.timeout(5000),
  });
  const type = response.headers.get("Content-Type")?.split(";")[0].trim();
  if (
    !response.ok ||
    ![
      "image/x-icon",
      "image/vnd.microsoft.icon",
      "image/png",
      "image/jpeg",
      "image/webp",
      "image/gif",
    ].includes(type)
  ) {
    await response.body?.cancel();
    throw new HttpError(502, "图标暂不可用");
  }
  return new Response(response.body, {
    headers: {
      "Content-Type": type,
      "Cache-Control": "public, max-age=86400",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

// ---------------- TLS 指纹（仅读 Cloudflare 提供的可信元数据）----------------

function tlsFingerprint(request) {
  const cf = request.cf;
  const text = (v) => (typeof v === "string" && v.length > 0 ? v : null);
  return {
    source: cf ? "cloudflare" : null,
    ja3: text(cf?.botManagement?.ja3Hash),
    ja4: text(cf?.botManagement?.ja4),
    tlsVersion: text(cf?.tlsVersion),
    tlsCipher: text(cf?.tlsCipher),
  };
}

// ---------------- 内置算力验证（替代 Turnstile；无需外部密钥）----------------
// 流程：GET /browser/challenges 领取 challenge → 浏览器算出 answer 使
// sha256(nonce + ":" + answer) 以 "00" 开头 → POST /browser/challenges/verify
// 或在 /ping/start 里附带 verification。challenge 5 分钟过期，一次有效。

const POW_CHALLENGES = new Map();
const POW_DIFFICULTY = 2; // 哈希前缀 0 的个数（十六进制位）

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return [...new Uint8Array(buf)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function issueChallenge() {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  const nonce = [...bytes]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  POW_CHALLENGES.set(nonce, Date.now() + 300000);
  if (POW_CHALLENGES.size > 1000) {
    const now = Date.now();
    for (const [k, v] of POW_CHALLENGES) if (v <= now) POW_CHALLENGES.delete(k);
  }
  return { nonce, difficulty: POW_DIFFICULTY, expiresIn: 300 };
}

function challengeConfig() {
  return {
    providers: [
      {
        id: "pow",
        name: "内置算力验证",
        configured: true,
        note: "无需外部密钥，浏览器端做一次轻量计算即可通过",
      },
    ],
    challenge: issueChallenge(),
  };
}

async function verifyPow(body) {
  if (!body || body.provider !== "pow")
    throw new HttpError(400, "请选择验证服务");
  const nonce = body.challenge;
  const answer = body.answer;
  if (
    typeof nonce !== "string" ||
    typeof answer !== "string" ||
    !nonce ||
    !answer ||
    answer.length > 64
  )
    throw new HttpError(400, "验证凭证无效，请重新验证");
  const expiresAt = POW_CHALLENGES.get(nonce);
  if (!expiresAt || expiresAt < Date.now())
    throw new HttpError(400, "验证已过期，请重新验证");
  const hash = await sha256Hex(nonce + ":" + answer);
  if (!hash.startsWith("0".repeat(POW_DIFFICULTY)))
    return { success: false, message: "验证未通过，请重新验证" };
  POW_CHALLENGES.delete(nonce);
  return {
    success: true,
    message: "本站本次验证通过",
    verifiedAt: new Date().toISOString(),
  };
}

// ---------------- 全球 Ping（Globalping）----------------

// 静态备用节点（Globalping 探针接口不可用时使用）。
const STATIC_NODES = [
  { id: "n01", name: "中国上海", cc: "cn", city: "Shanghai", continent: "亚洲" },
  { id: "n02", name: "中国香港", cc: "hk", city: "Hong Kong", continent: "亚洲" },
  { id: "n03", name: "日本东京", cc: "jp", city: "Tokyo", continent: "亚洲" },
  { id: "n04", name: "新加坡", cc: "sg", city: "Singapore", continent: "亚洲" },
  { id: "n05", name: "越南胡志明", cc: "vn", city: "Ho Chi Minh City", continent: "亚洲" },
  { id: "n06", name: "印尼雅加达", cc: "id", city: "Jakarta", continent: "亚洲" },
  { id: "n07", name: "印度德里", cc: "in", city: "Delhi", continent: "亚洲" },
  { id: "n08", name: "阿联酋迪拜", cc: "ae", city: "Dubai", continent: "亚洲" },
  { id: "n09", name: "美国洛杉矶", cc: "us", city: "Los Angeles", continent: "美洲" },
  { id: "n10", name: "美国亚特兰大", cc: "us", city: "Atlanta", continent: "美洲" },
  { id: "n11", name: "加拿大温哥华", cc: "ca", city: "Vancouver", continent: "美洲" },
  { id: "n12", name: "巴西圣保罗", cc: "br", city: "Sao Paulo", continent: "美洲" },
  { id: "n13", name: "德国法兰克福", cc: "de", city: "Frankfurt", continent: "欧洲" },
  { id: "n14", name: "荷兰阿姆斯特丹", cc: "nl", city: "Amsterdam", continent: "欧洲" },
  { id: "n15", name: "法国巴黎", cc: "fr", city: "Paris", continent: "欧洲" },
  { id: "n16", name: "瑞典斯德哥尔摩", cc: "se", city: "Stockholm", continent: "欧洲" },
  { id: "n17", name: "瑞士苏黎世", cc: "ch", city: "Zurich", continent: "欧洲" },
  { id: "n18", name: "西班牙马德里", cc: "es", city: "Madrid", continent: "欧洲" },
  { id: "n19", name: "俄罗斯莫斯科", cc: "ru", city: "Moscow", continent: "欧洲" },
  { id: "n20", name: "土耳其伊斯坦布尔", cc: "tr", city: "Istanbul", continent: "欧洲" },
];

async function startPing(input) {
  const host = target(input.host);
  if (
    input.protocol !== undefined &&
    !["icmp", "https"].includes(input.protocol)
  )
    throw new HttpError(400, "不支持此测量协议");
  let locations;
  if (input.regions) {
    const allowed = ["AF", "AS", "EU", "NA", "OC", "SA"];
    if (
      !Array.isArray(input.regions) ||
      !input.regions.length ||
      input.regions.some((r) => !allowed.includes(r)) ||
      !Number.isInteger(input.perRegion) ||
      input.perRegion < 1 ||
      new Set(input.regions).size * input.perRegion > 50
    )
      throw new HttpError(400, "单批请选择有效地区及 1–50 个探针");
    locations = [...new Set(input.regions)].map((continent) => ({
      continent,
      limit: input.perRegion,
    }));
  } else {
    if (
      !Array.isArray(input.nodes) ||
      !input.nodes.length ||
      input.nodes.length > 50
    )
      throw new HttpError(400, "单批请选择 1–50 个地区");
    const catalog = input.nodes.some(
      (id) => typeof id === "string" && id.includes(":"),
    )
      ? await pingNodes()
      : STATIC_NODES;
    const selected = [...new Set(input.nodes)].map((id) =>
      catalog.find((node) => node.id === id),
    );
    if (selected.some((node) => !node))
      throw new HttpError(400, "无效的探测地区");
    locations = selected.map((node) => ({
      country: node.cc.toUpperCase(),
      city: node.city,
      limit: 1,
      ...(input.preferred === true && node.preferredAsn
        ? { asn: node.preferredAsn }
        : {}),
    }));
  }
  return upstream("https://api.globalping.io/v1/measurements", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      type: input.protocol === "https" ? "http" : "ping",
      target: host,
      measurementOptions:
        input.protocol === "https"
          ? {
              protocol: "HTTPS",
              port: 443,
              request: { method: "HEAD", path: "/" },
            }
          : { packets: 3 },
      locations,
      inProgressUpdates: true,
    }),
  });
}

async function pingResult(id) {
  if (!/^[a-zA-Z0-9_-]{8,80}$/.test(id))
    throw new HttpError(400, "无效的测量 ID");
  return upstream("https://api.globalping.io/v1/measurements/" + id, {
    headers: { "Content-Type": "application/json" },
  });
}

async function pingNodes() {
  return cached("ping-nodes", 300000, async () => {
    let probes;
    try {
      probes = await upstream("https://api.globalping.io/v1/probes", {}, 8000000);
    } catch {
      // 上游不可用时返回静态备用节点（按聚合格式输出）。
      return STATIC_NODES.map((n) => ({
        id: n.cc + ":" + n.city,
        cc: n.cc,
        continent: n.continent,
        city: n.city,
        name: n.name,
        probes: 1,
      }));
    }
    const cities = new Map();
    const providers = new Map();
    const majorCloud =
      /amazon|google|microsoft|digitalocean|ovh|hetzner|akamai|linode|vultr|choopa|oracle|alibaba|aliyun|tencent|huawei/i;
    const chinaCarrier =
      /chinanet|china telecom|china unicom|china mobile|cmnet|china networks inter-exchange/i;
    for (const probe of probes) {
      const loc = probe.location;
      if (!loc?.country || !loc.city) continue;
      const id = loc.country + ":" + loc.city;
      if (
        Number.isInteger(loc.asn) &&
        typeof loc.network === "string" &&
        (loc.country === "CN" ? chinaCarrier : majorCloud).test(loc.network)
      ) {
        const key = id + ":" + loc.asn;
        const provider = providers.get(key) ?? {
          cityId: id,
          asn: loc.asn,
          network: loc.network,
          count: 0,
        };
        provider.count++;
        providers.set(key, provider);
      }
      const existing = cities.get(id);
      if (existing) existing.probes++;
      else
        cities.set(id, {
          id,
          cc: loc.country.toLowerCase(),
          continent: loc.continent,
          city: loc.city,
          name: loc.country,
          probes: 1,
        });
    }
    for (const provider of providers.values()) {
      const city = cities.get(provider.cityId);
      if (
        !city.preferredAsn ||
        provider.count > city.preferredProbes ||
        (provider.count === city.preferredProbes &&
          provider.asn < city.preferredAsn)
      ) {
        city.preferredAsn = provider.asn;
        city.preferredNetwork = provider.network;
        city.preferredProbes = provider.count;
      }
    }
    return [...cities.values()].sort(
      (a, b) => a.cc.localeCompare(b.cc) || a.city.localeCompare(b.city),
    );
  });
}

// ---------------- 服务状态：44 个服务清单 ----------------
// url 为各服务官方状态接口；statuspage 类服务走通用解析，特殊服务见下方解析器。

const SERVICES = [
  { id: "telegram", name: "Telegram", group: "社区", url: "https://uptimerobot.com/api/pulse/monitors/telegram", page: "https://uptimerobot.com/is-it-down/telegram/", icon: "https://icons.duckduckgo.com/ip3/telegram.org.ico", note: "第三方来源：UptimeRobot，仅监测 telegram.org 网站可用性，不代表 Telegram 全球消息收发状态。" },
  { id: "0", name: "Cloudflare", group: "云服务", url: "https://www.cloudflarestatus.com/api/v2/summary.json", page: "https://www.cloudflarestatus.com" },
  { id: "1", name: "Supabase", group: "云服务", url: "https://status.supabase.com/api/v2/summary.json", page: "https://status.supabase.com" },
  { id: "2", name: "SendGrid", group: "开发", url: "https://status.sendgrid.com/api/v2/summary.json", page: "https://status.twilio.com" },
  { id: "3", name: "Twilio", group: "开发", url: "https://status.twilio.com/api/v2/summary.json", page: "https://status.twilio.com" },
  { id: "4", name: "Claude (Anthropic)", group: "AI", url: "https://status.claude.com/api/v2/summary.json", page: "https://status.claude.com", icon: "https://icons.duckduckgo.com/ip3/claude.ai.ico" },
  { id: "5", name: "Cursor", group: "AI", url: "https://status.cursor.com/api/v2/summary.json", page: "https://status.cursor.com" },
  { id: "6", name: "ElevenLabs", group: "AI", url: "https://status.elevenlabs.io/api/v2/summary.json", page: "https://status.elevenlabs.io/" },
  { id: "8", name: "Groq", group: "AI", url: "https://groqstatus.com/api/v2/summary.json", page: "https://groqstatus.com/" },
  { id: "9", name: "OpenAI", group: "AI", url: "https://status.openai.com/api/v2/summary.json", page: "https://status.openai.com/", icon: "https://icons.duckduckgo.com/ip3/openai.com.ico" },
  { id: "10", name: "Perplexity", group: "AI", url: "https://status.perplexity.com/api/v2/summary.json", page: "https://status.perplexity.com", icon: "https://icons.duckduckgo.com/ip3/www.perplexity.ai.ico" },
  { id: "11", name: "Replicate", group: "AI", url: "https://www.cloudflarestatus.com/api/v2/summary.json", page: "https://www.cloudflarestatus.com/services?search=replicate", icon: "https://icons.duckduckgo.com/ip3/replicate.com.ico", note: "Replicate 已迁入 Cloudflare 官方状态页，仅展示 Replicate 组件及关联事件。" },
  { id: "12", name: "DigitalOcean", group: "云服务", url: "https://status.digitalocean.com/api/v2/summary.json", page: "http://status.digitalocean.com" },
  { id: "13", name: "Fly.io", group: "云服务", url: "https://status.flyio.net/api/v2/summary.json", page: "https://status.flyio.net" },
  { id: "14", name: "Netlify", group: "云服务", url: "https://www.netlifystatus.com/api/v2/summary.json", page: "https://www.netlifystatus.com" },
  { id: "15", name: "Vercel", group: "云服务", url: "https://www.vercel-status.com/api/v2/summary.json", page: "https://www.vercel-status.com" },
  { id: "16", name: "Atlassian", group: "开发", url: "https://status.atlassian.com/api/v2/summary.json", page: "https://status.atlassian.com" },
  { id: "17", name: "Clerk", group: "开发", url: "https://status.clerk.com/api/v2/summary.json", page: "https://status.clerk.com/" },
  { id: "18", name: "Figma", group: "开发", url: "https://status.figma.com/api/v2/summary.json", page: "https://status.figma.com" },
  { id: "19", name: "GitHub", group: "开发", url: "https://www.githubstatus.com/api/v2/summary.json", page: "https://www.githubstatus.com" },
  { id: "20", name: "Notion", group: "开发", url: "https://www.notion-status.com/api/v2/summary.json", page: "https://www.notion-status.com/" },
  { id: "21", name: "Postman", group: "开发", url: "https://status.postman.com/api/v2/summary.json", page: "https://status.postman.com" },
  { id: "22", name: "Python Infrastructure", group: "开发", url: "https://status.python.org/api/v2/summary.json", page: "https://status.python.org" },
  { id: "23", name: "Sentry", group: "开发", url: "https://status.sentry.io/api/v2/summary.json", page: "https://status.sentry.io" },
  { id: "24", name: "Stripe", group: "开发", url: "https://www.stripestatus.com/api/v2/summary.json", page: "https://www.stripestatus.com" },
  { id: "25", name: "npm", group: "开发", url: "https://status.npmjs.org/api/v2/summary.json", page: "https://status.npmjs.org" },
  { id: "26", name: "Discord", group: "社区", url: "https://discordstatus.com/api/v2/summary.json", page: "https://discordstatus.com" },
  { id: "27", name: "Pinterest", group: "社区", url: "https://www.pintereststatus.com/api/v2/summary.json", page: "https://www.pintereststatus.com" },
  { id: "28", name: "Reddit", group: "社区", url: "https://www.redditstatus.com/api/v2/summary.json", page: "https://www.redditstatus.com" },
  { id: "29", name: "Twitch", group: "社区", url: "https://status.twitch.tv/api/v2/summary.json", page: "https://status.twitch.com" },
  { id: "30", name: "Zoom", group: "社区", url: "https://status.zoom.us/api/v2/summary.json", page: "https://www.zoomstatus.com" },
  { id: "31", name: "Gemini", group: "AI", url: "https://alkalimakersuite-pa.clients6.google.com/$rpc/google.internal.alkali.applications.makersuite.v1.MakerSuiteService/ListIncidentsHistory", page: "https://aistudio.google.com/status", icon: "https://icons.duckduckgo.com/ip3/gemini.google.com.ico", note: "仅涵盖 AI Studio / Gemini API，不代表 Gemini 聊天网站状态。" },
  { id: "32", name: "DeepSeek", group: "AI", url: "https://status.deepseek.com/feed.rss", page: "https://status.deepseek.com", icon: "https://icons.duckduckgo.com/ip3/www.deepseek.com.ico", note: "读取 DeepSeek 官方 RSS 中未解决的事件，已恢复事件不计入故障。" },
  { id: "33", name: "Grok", group: "AI", url: "https://status.x.ai/feed.xml", page: "https://status.x.ai", icon: "https://icons.duckduckgo.com/ip3/grok.com.ico", note: "读取官方 RSS 中未解决的事件；不包含状态页的实时监控指标。" },
  { id: "34", name: "通义千问", group: "AI", url: "https://status.aliyun.com/api/status/listCurrentProductStatus?regionId=non-regional", page: "https://status.aliyun.com/#/?region=non-regional", icon: "https://icons.duckduckgo.com/ip3/chat.qwen.ai.ico", note: "展示阿里云非区域性「百炼」产品状态，覆盖千问 API；不代表千问聊天网站状态。" },
  { id: "35", name: "Kimi", group: "AI", url: "https://status.moonshot.cn/api/v2/summary.json", page: "https://status.moonshot.cn", icon: "https://icons.duckduckgo.com/ip3/www.kimi.com.ico", note: "Moonshot AI 官方状态，涵盖 Kimi 与开放平台 API。" },
  { id: "dmit", name: "DMIT", group: "VPS", url: "https://does.dmit.fail/api/v1/status?locale=en", page: "https://does.dmit.fail/", icon: "https://icons.duckduckgo.com/ip3/dmit.io.ico", note: "展示官方汇总与机房线路状态；完整事件请查看官方状态页。" },
  { id: "bandwagonhost", name: "搬瓦工 (BandwagonHost)", group: "VPS", url: "https://bwhstatus.com/", page: "https://bwhstatus.com/", icon: "https://icons.duckduckgo.com/ip3/bandwagonhost.com.ico", note: "读取官方页面的当前汇总状态；完整事件请查看官方状态页。" },
  { id: "aws", name: "Amazon Web Services (AWS)", group: "云服务", url: "https://health.aws.amazon.com/public/currentevents", page: "https://health.aws.amazon.com/health/status", icon: "https://icons.duckduckgo.com/ip3/aws.amazon.com.ico", note: "仅涵盖公开服务事件，不代表账户或实例的专属健康状态。" },
  { id: "aliyun", name: "阿里云", group: "云服务", url: "https://status.aliyun.com/api/status/listEventInProgress", page: "https://status.aliyun.com/", icon: "https://icons.duckduckgo.com/ip3/aliyun.com.ico", note: "读取阿里云官方进行中事件，已恢复事件不计入当前故障。" },
  { id: "tencent-cloud", name: "腾讯云", group: "云服务", url: "https://status.tencentcloud.com/v1/api/status/DescribeRegions?BelongSite=1", page: "https://status.tencentcloud.com/", icon: "https://icons.duckduckgo.com/ip3/tencentcloud.com.ico", note: "读取腾讯云官方区域状态与当前公告，隐藏或已恢复公告不计入故障。" },
  { id: "google-cloud", name: "Google Cloud", group: "云服务", url: "https://status.cloud.google.com/incidents.json", page: "https://status.cloud.google.com/", icon: "https://icons.duckduckgo.com/ip3/cloud.google.com.ico", note: "仅涵盖公开服务事件，不代表账户或实例的专属健康状态。" },
  { id: "azure", name: "Microsoft Azure", group: "云服务", url: "https://azure.status.microsoft/en-us/status/", page: "https://azure.status.microsoft/en-us/status/", icon: "https://icons.duckduckgo.com/ip3/azure.microsoft.com.ico", note: "读取 Azure 官方 Current Impact；仅涵盖公开的广泛影响事件，不代表账户专属健康状态。" },
  { id: "oracle-cloud", name: "Oracle Cloud (OCI)", group: "云服务", url: "https://ocistatus.oraclecloud.com/api/v2/status.json", page: "https://ocistatus.oraclecloud.com/", icon: "https://icons.duckduckgo.com/ip3/oracle.com.ico", note: "展示 OCI 商业区域的官方汇总状态；区域详情请查看官方页面。" },
];

// 把 Atlassian 风格的状态页（page.status）统一成 indicator 格式。
function normalizeStatus(data) {
  if (data.status?.indicator) return data;
  const states = {
    UP: { indicator: "none", description: "正常运行" },
    HASISSUES: { indicator: "minor", description: "存在服务故障" },
    UNDERMAINTENANCE: { indicator: "maintenance", description: "维护中" },
  };
  const status = states[data.page?.status];
  if (!status) return data;
  const incidents = [
    ...(data.activeIncidents ?? []).filter((i) => i.status !== "RESOLVED"),
    ...(data.activeMaintenances ?? []).filter((i) => i.status === "INPROGRESS"),
  ];
  return {
    status,
    incidents: incidents.map((item) => ({
      id: item.id ?? item.url,
      name: item.name,
      status: item.status,
      updated_at: item.updatedAt ?? item.started ?? item.start,
      shortlink: item.url,
    })),
  };
}

const statusUnavailable = () => new HttpError(502, "官方状态数据暂不可用");
const statusSummary = (indicator, description, incidents) => ({
  status: { indicator, description },
  ...(incidents ? { incidents } : {}),
});

// ---- RSS 解析（DeepSeek / Grok）----

function rssItems(xml) {
  if (!/<rss\b/.test(xml) || !/<channel\b/.test(xml) || !/<\/channel>\s*<\/rss>\s*$/.test(xml))
    throw statusUnavailable();
  const items = [...xml.matchAll(/<item\b[^>]*>([\s\S]*?)<\/item>/g)];
  if (items.length !== (xml.match(/<item\b/g) ?? []).length)
    throw statusUnavailable();
  return items;
}

function rssField(body, tag) {
  const value =
    body.match(new RegExp("<" + tag + "\\b[^>]*>([\\s\\S]*?)</" + tag + ">"))?.[1].trim() ?? "";
  const decoded = value.startsWith("<![CDATA[") && value.endsWith("]]>")
    ? value.slice(9, -3)
    : value;
  return decoded.replace(
    /&(?:amp|lt|gt|quot|apos|#\d+|#x[\da-fA-F]+);/g,
    (entity) => {
      const named = { "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'" };
      if (named[entity]) return named[entity];
      const code = entity.startsWith("&#x")
        ? parseInt(entity.slice(3, -1), 16)
        : Number(entity.slice(2, -1));
      if (code < 0 || code > 0x10ffff) throw statusUnavailable();
      return String.fromCodePoint(code);
    },
  );
}

function parseDeepSeek(xml) {
  const incidents = [];
  for (const [, body] of rssItems(xml)) {
    const description = rssField(body, "description");
    const state = description
      .match(/<strong>\s*Status:\s*<\/strong>\s*([\w-]+)/i)?.[1]
      .toLowerCase();
    if (["resolved", "completed", "cancelled", "scheduled"].includes(state)) continue;
    if (!["investigating", "identified", "monitoring", "ongoing", "in_progress", "verifying"].includes(state))
      throw statusUnavailable();
    const id = rssField(body, "guid");
    const name = rssField(body, "title");
    const shortlink = rssField(body, "link");
    if (!id || !name || !shortlink.startsWith("https://status.deepseek.com/"))
      throw statusUnavailable();
    incidents.push({ id, name, status: state, shortlink });
  }
  return {
    status: {
      indicator: incidents.some((i) => ["investigating", "identified", "monitoring"].includes(i.status))
        ? "minor"
        : incidents.length
          ? "maintenance"
          : "none",
      description: incidents.length ? "存在公开服务事件" : "订阅源未报告未解决事件",
    },
    incidents,
  };
}

function parseGrokFeed(xml) {
  const incidents = [];
  for (const [, body] of rssItems(xml)) {
    const metadata = body.replace(/<description\b[^>]*>[\s\S]*?<\/description>/g, "");
    const categories = [...metadata.matchAll(/<category>([^<]+)<\/category>/g)].map((m) =>
      m[1].trim().toLowerCase(),
    );
    if (categories.includes("resolved")) continue;
    const description = rssField(body, "description");
    const state = description
      .match(/<h3>\s*Status:\s*([\w -]+)\s*<\/h3>/i)?.[1]
      .trim()
      .toLowerCase();
    if (!state || !["investigating", "identified", "monitoring", "open", "ongoing"].includes(state))
      throw statusUnavailable();
    const id = rssField(metadata, "guid");
    const name = rssField(metadata, "title");
    const shortlink = rssField(metadata, "link");
    if (!id || !name || !shortlink.startsWith("https://status.x.ai/"))
      throw statusUnavailable();
    const dates = [...description.matchAll(/<strong>([^<]+)<\/strong>/g)]
      .map((m) => Date.parse(m[1]))
      .filter(Number.isFinite);
    const published = Date.parse(rssField(metadata, "pubDate"));
    if (Number.isFinite(published)) dates.push(published);
    incidents.push({
      id,
      name,
      status: state,
      shortlink,
      ...(dates.length ? { updated_at: new Date(Math.max(...dates)).toISOString() } : {}),
    });
  }
  return {
    status: {
      indicator: incidents.length ? "minor" : "none",
      description: incidents.length ? "存在公开服务事件" : "订阅源未报告未解决事件",
    },
    incidents,
  };
}

function parseGemini(data) {
  const rows = data?.[0]?.[0];
  if (!Array.isArray(rows)) throw statusUnavailable();
  const incidents = [];
  for (const row of rows) {
    if (!Array.isArray(row) || typeof row[0] !== "string" || !Array.isArray(row[3]) || !row[3].length)
      throw statusUnavailable();
    const updates = [...row[3]].sort(
      (a, b) => Number(b[2]?.[0]) - Number(a[2]?.[0]),
    );
    const latest = updates[0];
    if (![1, 2, 3, 4, 5].includes(latest[0]) || !Number.isFinite(Number(latest[2]?.[0])))
      throw statusUnavailable();
    if (latest[0] === 4) continue;
    incidents.push({
      id: row[0],
      name: row[1],
      status: latest[0] === 1 ? "investigating" : "monitoring",
      updated_at: new Date(Number(latest[2][0]) * 1000).toISOString(),
      shortlink: "https://aistudio.google.com/status",
    });
  }
  return {
    status: {
      indicator: incidents.length ? "minor" : "none",
      description: incidents.length ? "存在服务故障" : "正常运行",
    },
    incidents,
  };
}

function parseReplicate(data) {
  const component = data?.components?.find((item) => item.id === "fvgfcmy66tdr");
  const states = {
    operational: "none",
    degraded_performance: "minor",
    partial_outage: "minor",
    major_outage: "major",
    under_maintenance: "maintenance",
  };
  if (
    !component ||
    !states[component.status] ||
    !Array.isArray(data.incidents) ||
    !Array.isArray(data.scheduled_maintenances)
  )
    throw statusUnavailable();
  const affects = (item) =>
    item.components?.some((part) => part.id === component.id);
  const incidents = data.incidents.filter(
    (item) =>
      ["investigating", "identified", "monitoring"].includes(item.status) &&
      affects(item),
  );
  const maintenance = data.scheduled_maintenances.filter(
    (item) =>
      ["in_progress", "verifying"].includes(item.status) && affects(item),
  );
  return {
    status: {
      indicator:
        component.status === "operational" && maintenance.length
          ? "maintenance"
          : states[component.status],
      description: component.status,
    },
    components: [component],
    incidents: [...incidents, ...maintenance],
  };
}

function parseTelegramStatus(data, now = Date.now()) {
  const checked = Date.parse(data?.lastCheck);
  if (
    data?.slug !== "telegram" ||
    data?.url !== "telegram.org" ||
    !["UP", "DOWN"].includes(data?.status) ||
    !Number.isFinite(checked) ||
    checked > now + 60000 ||
    now - checked > 30 * 60000
  )
    throw new HttpError(502, "第三方状态数据暂不可用");
  const up = data.status === "UP";
  return {
    status: {
      indicator: up ? "none" : "major",
      description: up ? "第三方网站监测正常" : "第三方网站监测异常",
    },
    checkedAt: new Date(checked).toISOString(),
    components: [
      {
        id: "telegram-website",
        name: "telegram.org (UptimeRobot)",
        status: up ? "operational" : "major_outage",
      },
    ],
  };
}

async function getAiStatus(service) {
  if (service.id === "telegram")
    return parseTelegramStatus(await upstream(service.url));
  if (service.id === "33")
    return parseGrokFeed(await upstream(service.url, {}, 2000000, "text"));
  if (service.id === "11")
    return parseReplicate(
      await upstream(service.url, {
        headers: { "User-Agent": "One-IP/1.0" },
      }),
    );
  if (service.id === "32") {
    let html;
    try {
      html = await upstream(service.url, {}, 2000000, "text");
    } catch {
      throw new HttpError(502, "DeepSeek 官方订阅源连接失败，请稍后重试或查看官方页面。");
    }
    try {
      return parseDeepSeek(html);
    } catch {
      throw new HttpError(502, "DeepSeek 官方状态数据解析失败，请查看官方页面。");
    }
  }
  if (service.id === "31") {
    const html = await upstream(service.page, {}, 2000000, "text");
    const keys = [...new Set(html.match(/AIza[\w-]+/g) ?? [])];
    for (const key of keys) {
      const response = await fetch(service.url, {
        method: "POST",
        body: "[]",
        signal: AbortSignal.timeout(10000),
        headers: {
          "Content-Type": "application/json+protobuf",
          "X-Goog-Api-Key": key,
          Referer: "https://aistudio.google.com/",
        },
      });
      if (!response.ok) {
        await response.body?.cancel();
        continue;
      }
      return parseGemini(await boundedJson(response));
    }
    throw statusUnavailable();
  }
  return upstream(service.url);
}

// ---- 云厂商 / VPS 状态解析 ----

async function sourceText(url, maxBytes = 2000000) {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(10000),
    redirect: "manual",
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new HttpError(
      response.status === 429 ? 429 : 502,
      "官方状态数据暂不可用",
    );
  }
  const reader = response.body?.getReader();
  if (!reader) throw statusUnavailable();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw statusUnavailable();
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  const encoding =
    bytes[0] === 0xfe && bytes[1] === 0xff
      ? "utf-16be"
      : bytes[0] === 0xff && bytes[1] === 0xfe
        ? "utf-16le"
        : "utf-8";
  return new TextDecoder(encoding).decode(bytes);
}

function parseDmit(data) {
  const states = {
    operational: "none",
    degraded: "minor",
    partial_outage: "minor",
    major_outage: "major",
    maintenance: "maintenance",
    under_maintenance: "maintenance",
  };
  if (!states[data?.status] || !Array.isArray(data.services))
    throw statusUnavailable();
  return {
    ...statusSummary(states[data.status], data.status),
    components: data.services.map((s) => ({
      id: s.slug,
      name: s.group + " / " + s.name,
      status: s.status === "degraded" ? "degraded_performance" : s.status,
    })),
  };
}

function parseGoogleCloud(data) {
  if (
    !Array.isArray(data) ||
    data.some((i) => !i?.id || !i.begin || typeof i.external_desc !== "string")
  )
    throw statusUnavailable();
  const active = data.filter((i) => !i.end);
  return statusSummary(
    active.some((i) => i.severity === "high")
      ? "major"
      : active.length
        ? "minor"
        : "none",
    active.length ? "存在服务故障" : "正常运行",
    active.map((i) => ({
      id: i.id,
      name: i.external_desc,
      status: i.most_recent_update?.status ?? "investigating",
      updated_at: i.modified ?? i.begin,
      shortlink: "https://status.cloud.google.com/incidents/" + encodeURIComponent(i.id),
    })),
  );
}

function parseAws(data) {
  if (
    !Array.isArray(data) ||
    data.some((i) => !i?.arn || !["0", "1", "2", "3"].includes(String(i.status)))
  )
    throw statusUnavailable();
  const active = data.filter((i) => String(i.status) !== "0");
  return statusSummary(
    active.some((i) => String(i.status) === "3")
      ? "major"
      : active.length
        ? "minor"
        : "none",
    active.length ? "存在服务故障" : "正常运行",
    active.map((i) => ({
      id: i.arn,
      name: i.service_name + " (" + i.region_name + ") — " + i.summary,
      status: { 1: "Impacted", 2: "Degraded", 3: "Disrupted" }[i.status],
      updated_at: new Date(
        Math.max(
          Number(i.date),
          ...(i.event_log ?? []).map((u) => Number(u.timestamp)),
        ) * 1000,
      ).toISOString(),
      shortlink: "https://health.aws.amazon.com/health/status",
    })),
  );
}

function parseBandwagon(html) {
  if (!html.includes("<title>BandwagonHost Status</title>"))
    throw statusUnavailable();
  const label = html
    .match(/<span\s+class="summary\s+summary-[\w-]+"\s*>([^<]+)<\/span>/)?.[1]
    .trim();
  const description = html.match(/<h1>([^<]+)<\/h1>/)?.[1].trim();
  if (!label || !description) throw statusUnavailable();
  if (label === "Operational" && description === "All systems operational")
    return statusSummary(
      "none",
      description,
      /class="empty">No incidents in the last \d+ days\.<\/p>/.test(html) ? [] : undefined,
    );
  if (/maintenance/i.test(label)) return statusSummary("maintenance", description);
  if (/outage|disruption|degraded|incident/i.test(label))
    return statusSummary("minor", description);
  throw statusUnavailable();
}

const isoTime = (v) => {
  if (v == null || v === "") return undefined;
  const d = new Date(v);
  return Number.isFinite(d.getTime()) ? d.toISOString() : undefined;
};

function parseAliyun(data) {
  if (data?.success !== true || data.code !== 200 || !Array.isArray(data.data))
    throw statusUnavailable();
  if (
    data.data.some(
      (i) =>
        i?.id == null ||
        typeof i.title !== "string" ||
        !["ALARM", "NOTIFICATION", "NORMAL"].includes(i.eventType),
    )
  )
    throw statusUnavailable();
  const active = data.data.filter(
    (i) => !i.endTime && i.eventType !== "NORMAL",
  );
  return statusSummary(
    active.some((i) => i.eventType === "ALARM")
      ? "major"
      : active.length
        ? "minor"
        : "none",
    active.length ? "存在服务故障或提示" : "正常运行",
    active.map((i) => ({
      id: String(i.id),
      name: i.title,
      status: i.eventType,
      updated_at: isoTime(i.lastUpdateTime ?? i.startTime),
      shortlink:
        "https://status.aliyun.com/#/eventDetail?eventId=" + encodeURIComponent(i.id),
    })),
  );
}

function tencentData(data) {
  if (data?.Response?.Error || !data?.Response?.Data) throw statusUnavailable();
  return data.Response.Data;
}

function tencentRegions(data) {
  const areas = tencentData(data).AreaDetailList;
  if (
    !Array.isArray(areas) ||
    !areas.length ||
    areas.some((a) => !Array.isArray(a?.RegionList))
  )
    throw statusUnavailable();
  const regions = areas.flatMap((a) => a.RegionList);
  if (
    !regions.length ||
    regions.some(
      (r) =>
        typeof r?.RegionId !== "string" ||
        typeof r.RegionName !== "string" ||
        typeof r.EventsIn !== "boolean",
    )
  )
    throw statusUnavailable();
  return regions;
}

function parseTencentProducts(data, region) {
  const categories = tencentData(data).CategoryList;
  if (
    !Array.isArray(categories) ||
    !categories.length ||
    categories.some((c) => !Array.isArray(c?.ProductList))
  )
    throw statusUnavailable();
  const products = categories.flatMap((c) => c.ProductList);
  if (
    !products.length ||
    products.some(
      (p) => !["NORMAL", "NOTIFY", "ABNORMAL"].includes(p?.CurrentStatus),
    )
  )
    throw statusUnavailable();
  return products
    .filter((p) => p.CurrentStatus !== "NORMAL")
    .map((p) => ({
      id: region.RegionId + "/" + p.ProductId,
      name: region.RegionName + " / " + p.ProductName,
      status: p.CurrentStatus,
      shortlink:
        "https://status.tencentcloud.com/?region=" + encodeURIComponent(region.RegionId),
    }));
}

function parseTencentBanner(data) {
  const banner = tencentData(data);
  if (
    typeof banner.IsShow !== "boolean" ||
    !["NORMAL", "NOTIFY", "ABNORMAL"].includes(banner.Status)
  )
    throw statusUnavailable();
  if (!banner.IsShow || banner.Status === "NORMAL") return [];
  if (banner.Id == null || typeof banner.Desc !== "string")
    throw statusUnavailable();
  return [
    {
      id: "notice/" + banner.Id,
      name: banner.Title || banner.Desc,
      status: banner.Status,
      shortlink: "https://status.tencentcloud.com/",
    },
  ];
}

async function tencentStatus(url) {
  const [regionData, bannerData] = await Promise.all([
    upstream(url),
    upstream(
      "https://status.tencentcloud.com/v1/api/status/DescribeHappening?BelongSite=1",
    ),
  ]);
  const regions = tencentRegions(regionData);
  const date = new Date().toISOString().slice(0, 10);
  const affected = regions.filter((r) => r.EventsIn);
  const details = await Promise.all(
    affected.map(async (region) => {
      const query = new URLSearchParams({
        BelongSite: "1",
        RegionId: region.RegionId,
        NumOfDay: "1",
        EndDate: date,
      });
      return parseTencentProducts(
        await upstream(
          "https://status.tencentcloud.com/v1/api/status/DescribeProductEventForRegionInPeriod?" + query,
        ),
        region,
      );
    }),
  );
  const incidents = [...parseTencentBanner(bannerData), ...details.flat()];
  return {
    ...statusSummary(
      incidents.some((i) => i.status === "ABNORMAL")
        ? "major"
        : incidents.length
          ? "minor"
          : "none",
      incidents.length ? "存在服务故障或提示" : "正常运行",
      incidents,
    ),
    components: regions.map((region) => ({
      id: region.RegionId,
      name: region.RegionName,
      status: incidents.some((i) => i.id.startsWith(region.RegionId + "/"))
        ? "degraded_performance"
        : "operational",
    })),
  };
}

function stripTags(html) {
  return html
    .replace(/<[^>]*>/g, " ")
    .replace(/&(?:nbsp|amp|lt|gt|quot|#39);/g, (e) =>
      ({ "&nbsp;": " ", "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#39;": "'" })[e],
    )
    .replace(/\s+/g, " ")
    .trim();
}

function parseAzure(html) {
  const table = html.match(
    /<table\b[^>]*data-zone-name="current-impact"[^>]*>([\s\S]*?)<\/table>/,
  )?.[1];
  if (!table) throw statusUnavailable();
  const rows = [...table.matchAll(/<tr\b[^>]*class="current-incident"[^>]*>([\s\S]*?)<\/tr>/g)].map(
    (m) => m[1],
  );
  if (!rows.length) throw statusUnavailable();
  const active = rows.filter(
    (row) =>
      !(
        /class="bg-green"/.test(row) &&
        stripTags(row).startsWith("There are currently no active events.")
      ),
  );
  if (active.some((row) => !stripTags(row) || !/<td\b/.test(row)))
    throw statusUnavailable();
  return statusSummary(
    active.length ? "major" : "none",
    active.length ? "存在公开服务事件" : "未报告广泛影响的事件",
    active.map((row, index) => ({
      id: "azure-current-" + index,
      name: stripTags(row).slice(0, 500),
      status: "investigating",
      shortlink: "https://azure.status.microsoft/en-us/status/",
    })),
  );
}

function parseQwenStatus(catalog, current) {
  if (
    catalog?.success !== true ||
    !Array.isArray(catalog.data) ||
    !catalog.data.some((g) =>
      g.productList?.some((p) => p.productId === "sfm"),
    ) ||
    current?.success !== true ||
    !Array.isArray(current.data) ||
    current.data.length !== 1
  )
    throw statusUnavailable();
  const { productStatus, eventDetails } = current.data[0] ?? {};
  if (
    !productStatus ||
    typeof productStatus !== "object" ||
    Array.isArray(productStatus) ||
    !eventDetails ||
    typeof eventDetails !== "object" ||
    Array.isArray(eventDetails)
  )
    throw statusUnavailable();
  const refs = productStatus.sfm ?? [];
  if (!Array.isArray(refs)) throw statusUnavailable();
  const events = refs.map((ref) => {
    const event = eventDetails[ref.eventId];
    if (!event) throw statusUnavailable();
    return event;
  });
  const result = parseAliyun({ success: true, code: 200, data: events });
  return {
    ...result,
    components: [
      {
        id: "sfm",
        name: "大模型服务平台百炼",
        status:
          result.status.indicator === "none"
            ? "operational"
            : result.status.indicator === "major"
              ? "major_outage"
              : "degraded_performance",
      },
    ],
  };
}

async function getCloudStatus(service) {
  if (service.id === "34") {
    const [catalog, current] = await Promise.all([
      upstream(
        "https://status.aliyun.com/api/status/listProductForAllTypeInRegion?regionId=non-regional",
      ),
      upstream(service.url),
    ]);
    return parseQwenStatus(catalog, current);
  }
  if (service.id === "aliyun") return parseAliyun(await upstream(service.url));
  if (service.id === "tencent-cloud") return tencentStatus(service.url);
  if (service.id === "azure")
    return parseAzure(await sourceText(service.url, 8000000));
  if (service.id === "dmit") return parseDmit(await upstream(service.url));
  if (service.id === "bandwagonhost")
    return parseBandwagon(await sourceText(service.url));
  if (service.id === "google-cloud")
    return parseGoogleCloud(await upstream(service.url));
  if (service.id === "aws")
    return parseAws(JSON.parse(await sourceText(service.url)));
  return upstream(service.url);
}

// ---------------- IP 综合信息（并行合并）----------------

async function ipInfo(ip) {
  ip = publicIp(ip);
  const [geo, type, basic] = await Promise.allSettled([
    geoIp(ip),
    ipType(ip),
    ripeBasic(ip),
  ]);
  return {
    ip,
    geo: geo.status === "fulfilled" ? geo.value : null,
    type: type.status === "fulfilled" ? type.value : { available: false },
    network: basic.status === "fulfilled" ? basic.value : null,
    checkedAt: new Date().toISOString(),
  };
}

// ---------------- 测速（下载 / 上传）----------------

function bytesStream(total) {
  const chunk = new Uint8Array(65536).fill(120); // 字符 "x"
  let sent = 0;
  return new ReadableStream({
    pull(controller) {
      if (sent >= total) {
        controller.close();
        return;
      }
      const n = Math.min(65536, total - sent);
      controller.enqueue(chunk.subarray(0, n));
      sent += n;
    },
  });
}

async function speedtest(request, url) {
  if (request.method === "GET") {
    const n = Math.min(
      10485760,
      Math.max(1024, Number(url.searchParams.get("bytes")) || 1048576),
    );
    return new Response(bytesStream(n), {
      headers: {
        "Content-Type": "application/octet-stream",
        "Cache-Control": "no-store",
        "Content-Length": String(n),
      },
    });
  }
  // POST：读取上传体并回告字节数
  const reader = request.body?.getReader();
  let received = 0;
  if (reader) {
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > 10485760) throw new HttpError(413, "上传内容过大");
      }
    } finally {
      await reader.cancel().catch(() => {});
    }
  }
  return json({ received });
}

// ---------------- 路由入口 ----------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/worker" || url.pathname.startsWith("/worker/"))
      return new Response("Not found", { status: 404 });

    // 非 API 请求直接返回内嵌前端页面（不依赖 ASSETS）。
    if (url.pathname !== "/api" && !url.pathname.startsWith("/api/")) {
      return new Response(PAGE_HTML, {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        },
      });
    }

    try {
      const origin = request.headers.get("Origin");
      if (origin && origin !== url.origin)
        throw new HttpError(403, "仅支持同源调用");

      if (!["GET", "POST"].includes(request.method))
        throw new HttpError(405, "不支持此请求方法");

      const key = clientIp(request) ?? "local";
      const path = url.pathname.slice(4).replace(/\/$/, "");

      const bucket = request.method === "POST" ? "action" : "api";
      const limit = request.method === "POST" ? 10 : 180;
      if (!checkLimit(key + ":" + bucket, limit))
        throw new HttpError(429, "请求过于频繁，请一分钟后重试");

      const postOnly =
        path === "/ping/start" || path === "/browser/challenges/verify";
      const anyMethod = path === "/speedtest";
      if (
        (postOnly && request.method !== "POST") ||
        (!postOnly && !anyMethod && request.method !== "GET")
      )
        throw new HttpError(405, "不支持此请求方法");

      if (path === "/browser/tls-fingerprint")
        return json(tlsFingerprint(request));

      if (path === "/browser/challenges") return json(challengeConfig());

      if (path === "/browser/challenges/verify")
        return json(await verifyPow(await inputJson(request)));

      if (path.startsWith("/icons/"))
        return await siteIcon(decodeURIComponent(path.slice(7)));

      if (path === "/speedtest") return speedtest(request, url);

      if (path === "/me") {
        const data = cfGeo(request);
        if (!data.ip || key === "local")
          throw new HttpError(
            503,
            "当前环境没有真实访客公网 IP，请检查部署的访客 IP 配置；不会使用示例 IP。",
          );
        try {
          publicIp(data.ip);
        } catch {
          throw new HttpError(
            503,
            "当前环境没有真实访客公网 IP，请检查部署的访客 IP 配置；不会使用示例 IP。",
          );
        }
        return json(data);
      }

      if (path === "/ip/health") return json(await ipHealth(request));

      if (path.startsWith("/ip-type/"))
        return json(
          await ipType(decodeURIComponent(path.slice(9)), url.origin),
        );

      if (path.startsWith("/geoip/")) {
        const ip = publicIp(decodeURIComponent(path.slice(7)));
        return json(
          await cached("geoip:" + ip, 3600000, () => geoIp(ip)),
        );
      }

      if (path.startsWith("/ip/network/")) {
        const ip = publicIp(decodeURIComponent(path.slice(12)));
        return json(
          await cached(
            "ipnet:" + ip,
            300000,
            () => ipNetwork(ip),
            (data) =>
              data.routeAvailable &&
              data.ptrAvailable &&
              data.validations.every((item) => item.status !== "unavailable"),
          ),
        );
      }

      if (path.startsWith("/ip/lookup/")) {
        const ip = publicIp(decodeURIComponent(path.slice(11)));
        return json(
          await cached(
            "iplookup:" + ip,
            3600000,
            async () => {
              const [primary, secondary, registration] =
                await Promise.allSettled([
                  geoIp(ip),
                  secondaryGeo(ip),
                  lookupRegistration(ip),
                ]);
              const sources = [primary, secondary].flatMap((r) =>
                r.status === "fulfilled" ? [r.value] : [],
              );
              return {
                geo: sources[0] ?? { ip },
                sources,
                rdap:
                  registration.status === "fulfilled"
                    ? registration.value.data
                    : undefined,
              };
            },
            (data) => data.sources.length === 2 && data.rdap !== undefined,
          ),
        );
      }

      if (path.startsWith("/subdomains/")) {
        const value = decodeURIComponent(path.slice(12));
        return json(
          await cached("sub:" + value, 3600000, () => lookupSubdomains(value)),
        );
      }

      if (path.startsWith("/whois/lookup/")) {
        const query = registrationTarget(decodeURIComponent(path.slice(14)));
        return json(
          await cached(
            "whois:" + query,
            3600000,
            () => lookupRegistration(query),
          ),
        );
      }

      if (path === "/ping/nodes") return json(await pingNodes());

      if (path === "/ping/start") {
        const input = await inputJson(request);
        if (!input.verification || input.verification.provider !== "pow")
          throw new HttpError(403, "验证凭证无效，请重新验证");
        let verification;
        try {
          verification = await verifyPow(input.verification);
        } catch (e) {
          if (e instanceof HttpError)
            throw new HttpError(403, e.message);
          throw e;
        }
        if (!verification.success)
          throw new HttpError(403, verification.message);
        return json(await startPing(input));
      }

      if (path.startsWith("/ping/result/"))
        return json(await pingResult(path.slice(13)));

      if (path.startsWith("/status/")) {
        const service = SERVICES.find((s) => s.id === path.slice(8));
        if (!service) throw new HttpError(404, "未知服务");
        if (!service.url)
          throw new HttpError(
            503,
            "该服务未提供已接入的公开状态接口，请查看官方状态页",
          );
        return json(
          await cached(
            "status:" + service.id,
            60000,
            async () => {
              const data =
                service.group === "VPS" ||
                [
                  "aws",
                  "google-cloud",
                  "oracle-cloud",
                  "34",
                  "aliyun",
                  "tencent-cloud",
                  "azure",
                ].includes(service.id)
                  ? await getCloudStatus(service)
                  : await getAiStatus(service);
              return {
                ...normalizeStatus(data),
                fetchedAt: new Date().toISOString(),
                source: service.url,
              };
            },
            (data) => Boolean(data.status?.indicator),
          ),
        );
      }

      if (path.startsWith("/dns/lookup/")) {
        const domain = decodeURIComponent(path.slice(12));
        const type = url.searchParams.get("type") || "A";
        const resolver = url.searchParams.get("resolver") || "cf";
        return json(
          await cached(
            "dns:" + domain + ":" + type + ":" + resolver,
            60000,
            () => dnsLookup(domain, type, resolver),
          ),
        );
      }

      if (path.startsWith("/ip/cdn/"))
        return json(await detectCdn(decodeURIComponent(path.slice(8))));

      if (path.startsWith("/ip/"))
        return json(await ipInfo(decodeURIComponent(path.slice(4))));

      if (path.startsWith("/geo/"))
        return json(await geoIp(decodeURIComponent(path.slice(5))));

      throw new HttpError(404, "接口不存在");
    } catch (error) {
      if (error instanceof HttpError)
        return json({ error: error.message }, error.status);
      if (error instanceof URIError)
        return json({ error: "URL 编码无效" }, 400);
      // 不记录访客 IP、请求地址或上游错误体；不把堆栈返回给前端。
      console.error(
        JSON.stringify({ event: "api_error", type: error?.name ?? "Error" }),
      );
      return json({ error: "查询暂时失败，请稍后重试" }, 502);
    }
  },
};

// ---------------- 内嵌前端页面 ----------------
// 注意：整页放在模板字符串里，页面内的 JS 只用单引号与字符串拼接，
// 不使用反引号与 ${}，避免与外层模板字符串冲突。

const PAGE_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IP 网络工具箱</title>
<style>
:root{
  --bg:#fafafa; --surface:#ffffff; --surface2:#f8f9fb; --border:#e1e4e8;
  --text:#1a1a1a; --muted:#57606a; --accent:#2563eb; --accent2:#1d4ed8;
  --green:#1b8a2d; --green-soft:#d1fae5; --green-text:#065f46;
  --yellow:#b45309; --yellow-soft:#fef3c7; --red:#cf222e; --red-soft:#fee2e2;
  --blue-soft:#dbeafe; --blue-text:#1d4ed8; --gray:#6b7280;
  --shadow:0 1px 4px rgb(0 0 0 / 6%), 0 4px 12px rgb(0 0 0 / 4%);
}
.dark{
  --bg:#0d1117; --surface:#161b22; --surface2:#21262d; --border:#30363d;
  --text:#e6edf3; --muted:#c9d1d9; --accent:#3b82f6; --accent2:#93c5fd;
  --green:#4ade80; --green-soft:#123e31; --green-text:#a7f3d0;
  --yellow:#fbbf24; --yellow-soft:#3f2f04; --red:#f87171; --red-soft:#3f1d1d;
  --blue-soft:#162d4e; --blue-text:#93c5fd; --gray:#8b949e;
  --shadow:0 1px 4px rgb(0 0 0 / 40%), 0 4px 12px rgb(0 0 0 / 30%);
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;font-size:15px;line-height:1.6}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
header{border-bottom:1px solid var(--border)}
.nav{max-width:1000px;margin:0 auto;padding:14px 20px 10px;display:flex;align-items:center;gap:18px}
.logo{font-size:24px;font-weight:800;letter-spacing:-1px;color:var(--accent);line-height:1;white-space:nowrap}
.logo:hover{text-decoration:none}
.tabs{display:flex;gap:2px;flex:1;min-width:0;overflow-x:auto}
.tabs a{color:var(--muted);padding:7px 12px;border-radius:8px;font-size:14px;white-space:nowrap}
.tabs a:hover{color:var(--text);text-decoration:none;background:var(--surface2)}
.tabs a.active{color:var(--accent);font-weight:600}
.icon-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted);border-radius:8px;width:34px;height:34px;display:inline-flex;align-items:center;justify-content:center;cursor:pointer;flex:none;padding:0}
.icon-btn:hover{color:var(--text)}
.icon-btn svg{width:18px;height:18px}
.mnav{display:none}
main{max-width:1000px;margin:0 auto;padding:16px 20px 60px}
h1{font-size:26px;margin:4px 0 12px;line-height:1.3}
h2{font-size:17px;margin:22px 0 10px}
h3{font-size:15px;margin:0 0 10px;font-weight:600}
p{margin:6px 0}
.muted{color:var(--muted);font-size:13px}
.small{font-size:12px}
.page-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}
.page-head h1{font-size:15px;margin:0;font-weight:600}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 18px;margin-bottom:12px;box-shadow:var(--shadow)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:12px}
.grid .card{margin-bottom:0}
.ip-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.duo-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.bigip{font-size:24px;font-weight:700;letter-spacing:.5px;word-break:break-all;line-height:1.3}
.bigip a{color:inherit}
.score-num{font-size:56px;font-weight:800;line-height:1}
.eyebrow{font-size:12px;letter-spacing:.5px;color:var(--muted);margin-bottom:10px;display:flex;flex-wrap:wrap;align-items:center;gap:6px}
.row-between{display:flex;justify-content:space-between;align-items:center;gap:12px}
.row-between h3{margin:0}
.kv{display:grid;grid-template-columns:110px 1fr;gap:4px 10px;font-size:14px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;word-break:break-all}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600;margin:2px 4px 2px 0;white-space:nowrap}
.b-green{background:var(--green-soft);color:var(--green-text)}
.b-yellow{background:var(--yellow-soft);color:var(--yellow)}
.b-red{background:var(--red-soft);color:var(--red)}
.b-gray{background:#eef1f5;color:var(--muted)}
.dark .b-gray{background:#21262d;color:var(--muted)}
.b-blue{background:var(--blue-soft);color:var(--blue-text)}
.b-solid{background:var(--accent);color:#fff}
.btn{display:inline-block;background:var(--accent);color:#fff;border:0;border-radius:8px;padding:8px 16px;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none}
.btn:hover{filter:brightness(1.08);text-decoration:none}
.btn.ghost{background:var(--surface);color:var(--text);border:1px solid var(--border)}
.btn.ghost:hover{background:var(--surface2)}
.btn:disabled{opacity:.5;cursor:not-allowed}
input,select{width:100%;background:var(--surface);border:1px solid #d8dce0;color:var(--text);border-radius:8px;padding:9px 12px;font-size:14px;outline:none}
.dark input,.dark select{border-color:var(--border)}
input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(37,99,235,.2)}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.row input{flex:1;min-width:180px}
.row select{flex:0 0 150px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:9px 6px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;white-space:nowrap;font-size:13px}
td{word-break:break-all}
.ms{display:inline-block;font-family:ui-monospace,Menlo,monospace;font-weight:600;font-size:13px;background:var(--green-soft);color:var(--green-text);border-radius:6px;padding:2px 8px;white-space:nowrap}
.ms.mid{background:var(--yellow-soft);color:var(--yellow)}
.ms.slow{background:var(--red-soft);color:var(--red)}
.ms.bad{background:#eef1f5;color:var(--muted)}
.dark .ms.bad{background:#21262d}
.ms-orange{font-weight:600;color:#d97706;white-space:nowrap}
.dark .ms-orange{color:#fbbf24}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px;vertical-align:1px}
.dot.g{background:#22c55e}
.dot.y{background:#eab308}
.dot.r{background:#ef4444}
.dot.gr{background:#cbd5e1}
.bar{height:8px;background:#eef1f5;border-radius:99px;overflow:hidden;margin-top:6px}
.dark .bar{background:#21262d}
.bar i{display:block;height:100%;background:var(--accent);border-radius:99px}
.skel{color:var(--muted);padding:18px 0}
.err{background:var(--red-soft);border:1px solid rgba(207,34,46,.3);color:var(--red);border-radius:10px;padding:10px 14px;margin:10px 0;font-size:14px}
.dark .err{color:#fca5a5}
.note{background:#eff6ff;border:1px solid #bfdbfe;color:#1e40af;border-radius:10px;padding:10px 14px;margin:10px 0;font-size:13px}
.dark .note{background:#162d4e;border-color:#1e3a5f;color:#93c5fd}
.icon{width:20px;height:20px;border-radius:5px;vertical-align:-4px;margin-right:8px}
.flag{width:22px;height:16px;border-radius:2px;vertical-align:-2px;margin-right:8px;object-fit:cover}
.chip{display:inline-block;border:1px solid var(--border);border-radius:999px;padding:3px 11px;margin:2px 4px 2px 0;font-size:12px;color:var(--muted);cursor:pointer;background:var(--surface)}
.chip.on{border-color:var(--accent);color:var(--accent);background:var(--blue-soft)}
footer{max-width:1000px;margin:0 auto;padding:0 20px 40px;color:var(--muted);font-size:12px}
pre{background:#f8f9fb;border:1px solid var(--border);border-radius:10px;padding:12px;overflow:auto;font-size:12px;max-height:320px}
.dark pre{background:#0d1117}
.ping-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}
.tile{padding:8px 6px}
.tile-top{display:flex;align-items:center;justify-content:space-between;gap:8px}
.tile-name{display:flex;align-items:center;min-width:0;font-weight:600;font-size:14px}
.tile-name span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dots{display:flex;gap:3px;margin-top:7px}
.dots i{width:6px;height:6px;border-radius:50%;background:#d1d5db}
.dots i.g{background:#22c55e}
.dots i.y{background:#eab308}
.dots i.r{background:#ef4444}
.ip-card-top{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}
.ip-main{min-width:0;flex:1}
.ip-score{text-align:right;flex:none}
.ip-score .score-label{font-size:12px;color:var(--muted);margin-top:2px}
.ip-meta{margin-top:10px;font-size:14px}
.ip-meta p{margin:2px 0}
.ip-meta .sub{font-size:12px;color:var(--muted)}
.ai-row,.svc-row{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:7px 0;font-size:13px;border-bottom:1px solid var(--border)}
.ai-row:last-child,.svc-row:last-child{border-bottom:0}
.ai-row .nm,.svc-row .nm{display:flex;align-items:center;min-width:0;color:var(--text)}
.ai-row .nm span,.svc-row .nm span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.st-ok{color:var(--green);font-weight:600;white-space:nowrap}
.st-bad{color:var(--red);font-weight:600;white-space:nowrap}
.st-warn{color:var(--yellow);font-weight:600;white-space:nowrap}
.st-unk{color:var(--muted);font-weight:600;white-space:nowrap}
.egress-row{display:flex;align-items:center;gap:4px;padding:9px 0;border-bottom:1px solid var(--border)}
.egress-row:last-child{border-bottom:0}
.shortcut-feature{display:flex;align-items:center;gap:12px;padding:12px;border:1px solid var(--border);border-radius:10px;margin-bottom:10px;color:var(--text)}
.shortcut-feature:hover{background:var(--surface2);text-decoration:none}
.shortcut-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.shortcut-grid a{display:flex;align-items:center;gap:12px;padding:12px;border:1px solid var(--border);border-radius:10px;color:var(--text)}
.shortcut-grid a:hover{background:var(--surface2);text-decoration:none}
.shortcut-icon{flex:none;width:36px;height:36px;border-radius:9px;background:var(--surface2);display:flex;align-items:center;justify-content:center;color:var(--muted)}
.shortcut-icon img{width:22px;height:22px;border-radius:5px;margin:0}
.shortcut-icon svg{width:20px;height:20px}
.shortcut-label{flex:1;min-width:0}
.shortcut-label strong{display:block;font-size:14px}
.feature-grid{display:grid;grid-template-columns:repeat(8,1fr);gap:12px}
.feature-tile{display:flex;flex-direction:column;align-items:center;gap:8px;padding:14px 6px;border:1px solid var(--border);border-radius:10px;color:var(--text);text-align:center}
.feature-tile:hover{background:var(--surface2);text-decoration:none}
.feature-icon{width:44px;height:44px;border-radius:11px;background:var(--surface2);display:flex;align-items:center;justify-content:center}
.feature-icon img{width:26px;height:26px;border-radius:6px;margin:0}
.feature-icon svg{width:24px;height:24px}
.feature-label{font-size:13px;line-height:1.3}
.feature-sub{display:block;font-size:12px;color:var(--muted);margin-top:2px}
.promo-grid{grid-template-columns:repeat(4,1fr)}

.kbd-hint{margin-left:auto;font:11px/1 inherit;padding:5px 8px;border:1px solid var(--border);border-bottom-width:2px;border-radius:6px;color:var(--muted);background:var(--surface2)}
@media (max-width:900px){.feature-grid{grid-template-columns:repeat(4,1fr)}.promo-grid{grid-template-columns:repeat(2,1fr)}}

.shortcut-description{display:block;font-size:12px;color:var(--muted)}
.shortcut-arrow{color:var(--muted);flex:none}
@media (max-width:640px){
  .nav{padding:12px 16px 8px;gap:12px}
  .tabs{display:none}
  .mnav{display:flex;position:fixed;left:12px;right:12px;bottom:12px;z-index:20;background:var(--surface);border:1px solid var(--border);border-radius:20px;box-shadow:var(--shadow);padding:6px;justify-content:space-around}
  .mnav a{display:flex;flex-direction:column;align-items:center;gap:2px;color:var(--muted);font-size:11px;padding:5px 10px;border-radius:14px}
  .mnav a svg{width:20px;height:20px}
  .mnav a.active{color:var(--accent);background:var(--blue-soft);font-weight:600}
  .mnav a:hover{text-decoration:none}
  main{padding:14px 14px 100px}
  .ip-grid,.duo-grid{grid-template-columns:1fr}
  .ping-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
  .bigip{font-size:22px}
  .score-num{font-size:44px}
  .kv{grid-template-columns:96px 1fr}
  .row select{flex:1 1 100%}
  .shortcut-grid{grid-template-columns:1fr}
}
</style>
</head>
<body>
<header>
  <div class="nav">
    <a class="logo" href="#/">ip</a>
    <nav class="tabs" id="tabs">
      <a href="#/" data-route="">概览</a>
      <a href="#/network" data-route="network">网络检测</a>
      <a href="#/browser" data-route="browser">浏览器检测</a>
      <a href="#/ai" data-route="ai">AI 检测</a>
      <a href="#/status" data-route="status">服务状态</a>
    </nav>
    <button class="icon-btn" id="themeToggle" title="切换深色 / 浅色" aria-label="切换主题"><span id="themeIcon"></span></button>
  </div>
</header>
<nav class="mnav" id="mnav">
  <a href="#/" data-route=""><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>概览</a>
  <a href="#/network" data-route="network"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 7V3"/><path d="M15 7V3"/><path d="M7 7h10v4a5 5 0 0 1-10 0V7z"/><path d="M12 16v5"/></svg>网络</a>
  <a href="#/browser" data-route="browser"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a13 13 0 0 1 0 18"/><path d="M12 3a13 13 0 0 0 0 18"/></svg>浏览器</a>
  <a href="#/ai" data-route="ai"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9L12 3z"/><path d="M19 15l.8 2.2L22 18l-2.2.8L19 21l-.8-2.2L16 18l2.2-.8L19 15z"/></svg>AI</a>
  <a href="#/status" data-route="status"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3 8 4-16 3 8h4"/></svg>状态</a>
</nav>
<main id="app"><div class="skel">加载中…</div></main>
<footer>
  <p>本站为浏览器端 + 边缘节点联合诊断工具：连通性与出口探测在你的浏览器里完成，延迟为浏览器请求耗时中位数，不是 ICMP 延迟；机房出口可能被部分站点限流，个别站点失败不代表站点宕机。IP 归属与信誉仅供参考。</p>
  <p>数据来源：Cloudflare 边缘元数据、ipwho.is、ip.sb、Net.Coffee、ip-api、RIPEstat、RDAP、Globalping、各平台官方状态源。</p>
</footer>
<script>
'use strict';
/* ---------- 工具 ---------- */
function $(s){ return document.querySelector(s); }
function esc(s){ return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function msClass(ms){ if (ms == null || ms < 0) return 'bad'; if (ms < 150) return 'good'; if (ms < 400) return 'mid'; return 'slow'; }
function msText(ms){ if (ms == null || ms < 0) return '未连通'; return ms + ' ms'; }
function iconImg(host){ return '<img class="icon" loading="lazy" src="/api/icons/' + encodeURIComponent(host) + '" onerror="this.style.visibility=\\'hidden\\'" alt="">'; }
function api(path, opts){
  opts = opts || {};
  var ctrl = new AbortController();
  var timer = setTimeout(function(){ ctrl.abort(); }, opts.timeout || 12000);
  var init = { method: opts.method || 'GET', signal: ctrl.signal };
  if (opts.body) { init.headers = {'Content-Type': 'application/json'}; init.body = JSON.stringify(opts.body); }
  return fetch('/api' + path, init).then(function(res){
    clearTimeout(timer);
    return res.json().then(function(data){
      if (!res.ok) throw new Error((data && data.error) || ('请求失败（' + res.status + '）'));
      return data;
    });
  }).catch(function(e){
    clearTimeout(timer);
    if (e && e.name === 'AbortError') throw new Error('请求超时，请重试');
    throw e;
  });
}
function runLimited(items, limit, fn){
  var results = new Array(items.length);
  var idx = 0;
  function next(){
    if (idx >= items.length) return Promise.resolve();
    var i = idx++;
    return Promise.resolve(fn(items[i], i)).then(function(r){ results[i] = r; }).catch(function(e){ results[i] = { error: e }; }).then(next);
  }
  var workers = [];
  for (var w = 0; w < Math.min(limit, items.length); w++) workers.push(next());
  return Promise.all(workers).then(function(){ return results; });
}

/* ---------- 探测：图标加载 + no-cors 双信号（不要求跨域可读响应） ---------- */
function imgProbe(url, timeoutMs){
  return new Promise(function(resolve){
    var img = new Image();
    var t0 = performance.now();
    var done = false;
    var timer = setTimeout(function(){ finish(false); }, timeoutMs);
    function finish(ok){
      if (done) return;
      done = true;
      clearTimeout(timer);
      img.onload = img.onerror = null;
      img.src = '';
      resolve({ ok: ok, ms: Math.round(performance.now() - t0) });
    }
    img.onload = function(){ finish(true); };
    img.onerror = function(){ finish(false); };
    img.src = url + (url.indexOf('?') >= 0 ? '&' : '?') + '_=' + Date.now() + Math.floor(Math.random() * 100000);
  });
}
function fetchProbe(url, timeoutMs){
  var t0 = performance.now();
  return fetch(url, { mode: 'no-cors', cache: 'no-store', signal: AbortSignal.timeout(timeoutMs) })
    .then(function(){ return { ok: true, ms: Math.round(performance.now() - t0) }; })
    .catch(function(){ return { ok: false, ms: Math.round(performance.now() - t0) }; });
}
/* 先图标（能拿到耗时），失败再用 no-cors 请求确认可达性，最后重试一次图标。 */
function probeSite(host){
  var url = 'https://' + host + '/favicon.ico';
  return imgProbe(url, 8000).then(function(r){
    if (r.ok) return r;
    return fetchProbe(url, 8000).then(function(r2){
      if (r2.ok) return r2;
      return imgProbe(url, 8000);
    });
  });
}
/* 多轮探测取成功结果的中位数；全部失败则返回未连通。 */
function probeRounds(host, rounds){
  var jobs = [];
  for (var i = 0; i < rounds; i++) jobs.push(probeSite(host));
  return Promise.all(jobs).then(function(results){
    var oks = results.filter(function(r){ return r.ok; }).map(function(r){ return r.ms; }).sort(function(a, b){ return a - b; });
    if (!oks.length) return { ok: false, ms: -1, success: 0, total: rounds };
    return { ok: true, ms: oks[Math.floor(oks.length / 2)], success: oks.length, total: rounds };
  });
}

/* ---------- 固定数据 ---------- */
var AI_SITES = [
  { name: 'ChatGPT', host: 'chatgpt.com' },
  { name: 'Kimi', host: 'www.kimi.com' },
  { name: 'Gemini', host: 'gemini.google.com' },
  { name: '通义千问', host: 'chat.qwen.ai' },
  { name: 'DeepSeek', host: 'chat.deepseek.com' },
  { name: 'Grok', host: 'grok.com' },
  { name: 'Perplexity', host: 'www.perplexity.ai' },
  { name: 'Claude', host: 'claude.ai' }
];
var CONNECTIVITY_SITES = [
  { name: 'GitHub', host: 'github.com' },
  { name: 'Google', host: 'www.google.com' },
  { name: '微软', host: 'www.microsoft.com' },
  { name: '苹果', host: 'www.apple.com' },
  { name: 'Cloudflare', host: 'www.cloudflare.com' },
  { name: 'YouTube', host: 'www.youtube.com' },
  { name: '淘宝', host: 'www.taobao.com' },
  { name: '京东', host: 'www.jd.com' },
  { name: '百度', host: 'www.baidu.com' },
  { name: '哔哩哔哩', host: 'www.bilibili.com' },
  { name: '微信', host: 'weixin.qq.com' },
  { name: '字节跳动', host: 'www.bytedance.com' },
  { name: '知乎', host: 'www.zhihu.com' },
  { name: '亚马逊', host: 'www.amazon.com' }
];
var EXIT_GROUPS = [
  { name: 'AI 服务', sites: [['ChatGPT', 'chatgpt.com'], ['Claude', 'claude.ai'], ['Gemini', 'gemini.google.com'], ['DeepSeek', 'chat.deepseek.com'], ['Grok', 'grok.com'], ['Perplexity', 'www.perplexity.ai'], ['Kimi', 'www.kimi.com'], ['通义千问', 'chat.qwen.ai'], ['Poe', 'poe.com']] },
  { name: '加密货币', sites: [['币安', 'binance.com'], ['欧易', 'okx.com'], ['Bybit', 'bybit.com'], ['Coinbase', 'coinbase.com'], ['Kraken', 'kraken.com'], ['Bitget', 'bitget.com'], ['Gate.io', 'gate.io'], ['KuCoin', 'kucoin.com']] },
  { name: '跨境电商', sites: [['亚马逊', 'amazon.com'], ['eBay', 'ebay.com'], ['速卖通', 'aliexpress.com'], ['SHEIN', 'shein.com'], ['Etsy', 'etsy.com'], ['Shopee', 'shopee.com'], ['Lazada', 'lazada.com'], ['Wish', 'wish.com'], ['Temu', 'temu.com']] },
  { name: '流媒体', sites: [['Netflix', 'www.netflix.com']] },
  { name: '社交社区', sites: [['Telegram', 'web.telegram.org'], ['Reddit', 'www.reddit.com'], ['Discord', 'discord.com'], ['Pinterest', 'www.pinterest.com']] },
  { name: '开发平台', sites: [['GitHub', 'github.com'], ['GitLab', 'gitlab.com']] },
  { name: '实用工具', sites: [['Google', 'www.google.com'], ['微软', 'www.microsoft.com'], ['苹果', 'www.apple.com'], ['Dropbox', 'www.dropbox.com'], ['Notion', 'www.notion.so'], ['1Password', '1password.com'], ['Zoom', 'zoom.us']] },
  { name: '国内', sites: [['百度', 'www.baidu.com'], ['淘宝', 'www.taobao.com'], ['京东', 'www.jd.com'], ['哔哩哔哩', 'www.bilibili.com'], ['微信', 'weixin.qq.com']] },
  { name: '静态资源', sites: [['cdnjs', 'cdnjs.cloudflare.com'], ['jsDelivr', 'cdn.jsdelivr.net'], ['unpkg', 'unpkg.com'], ['Google Fonts', 'fonts.googleapis.com']] },
  { name: '测速服务', sites: [['Speedtest', 'www.speedtest.net']] }
];
var SERVICES = [
  ['telegram', 'Telegram', '社区', 'https://uptimerobot.com/is-it-down/telegram/'],
  ['0', 'Cloudflare', '云服务', 'https://www.cloudflarestatus.com'],
  ['1', 'Supabase', '云服务', 'https://status.supabase.com'],
  ['2', 'SendGrid', '开发', 'https://status.twilio.com'],
  ['3', 'Twilio', '开发', 'https://status.twilio.com'],
  ['4', 'Claude (Anthropic)', 'AI', 'https://status.claude.com'],
  ['5', 'Cursor', 'AI', 'https://status.cursor.com'],
  ['6', 'ElevenLabs', 'AI', 'https://status.elevenlabs.io/'],
  ['8', 'Groq', 'AI', 'https://groqstatus.com/'],
  ['9', 'OpenAI', 'AI', 'https://status.openai.com/'],
  ['10', 'Perplexity', 'AI', 'https://status.perplexity.com'],
  ['11', 'Replicate', 'AI', 'https://www.cloudflarestatus.com/services?search=replicate'],
  ['12', 'DigitalOcean', '云服务', 'http://status.digitalocean.com'],
  ['13', 'Fly.io', '云服务', 'https://status.flyio.net'],
  ['14', 'Netlify', '云服务', 'https://www.netlifystatus.com'],
  ['15', 'Vercel', '云服务', 'https://www.vercel-status.com'],
  ['16', 'Atlassian', '开发', 'https://status.atlassian.com'],
  ['17', 'Clerk', '开发', 'https://status.clerk.com/'],
  ['18', 'Figma', '开发', 'https://status.figma.com'],
  ['19', 'GitHub', '开发', 'https://www.githubstatus.com'],
  ['20', 'Notion', '开发', 'https://www.notion-status.com/'],
  ['21', 'Postman', '开发', 'https://status.postman.com'],
  ['22', 'Python Infrastructure', '开发', 'https://status.python.org'],
  ['23', 'Sentry', '开发', 'https://status.sentry.io'],
  ['24', 'Stripe', '开发', 'https://www.stripestatus.com'],
  ['25', 'npm', '开发', 'https://status.npmjs.org'],
  ['26', 'Discord', '社区', 'https://discordstatus.com'],
  ['27', 'Pinterest', '社区', 'https://www.pintereststatus.com'],
  ['28', 'Reddit', '社区', 'https://www.redditstatus.com'],
  ['29', 'Twitch', '社区', 'https://status.twitch.com'],
  ['30', 'Zoom', '社区', 'https://www.zoomstatus.com'],
  ['31', 'Gemini', 'AI', 'https://aistudio.google.com/status'],
  ['32', 'DeepSeek', 'AI', 'https://status.deepseek.com'],
  ['33', 'Grok', 'AI', 'https://status.x.ai'],
  ['34', '通义千问', 'AI', 'https://status.aliyun.com/#/?region=non-regional'],
  ['35', 'Kimi', 'AI', 'https://status.moonshot.cn'],
  ['dmit', 'DMIT', 'VPS', 'https://does.dmit.fail/'],
  ['bandwagonhost', '搬瓦工 (BandwagonHost)', 'VPS', 'https://bwhstatus.com/'],
  ['aws', 'Amazon Web Services (AWS)', '云服务', 'https://health.aws.amazon.com/health/status'],
  ['aliyun', '阿里云', '云服务', 'https://status.aliyun.com/'],
  ['tencent-cloud', '腾讯云', '云服务', 'https://status.tencentcloud.com/'],
  ['google-cloud', 'Google Cloud', '云服务', 'https://status.cloud.google.com/'],
  ['azure', 'Microsoft Azure', '云服务', 'https://azure.status.microsoft/en-us/status/'],
  ['oracle-cloud', 'Oracle Cloud (OCI)', '云服务', 'https://ocistatus.oraclecloud.com/']
];

/* ---------- 路由 ---------- */
var viewToken = 0;
function render(){
  var token = ++viewToken;
  var hash = location.hash.replace(/^#\\/?/, '');
  var parts = hash.split('/');
  var page = parts[0] || '';
  var arg = decodeURIComponent(parts.slice(1).join('/') || '');
  var app = document.getElementById('app');
  document.querySelectorAll('#tabs a, #mnav a').forEach(function(a){
    var r = a.getAttribute('data-route');
    var on = r === page ||
      ((page === '' || page === 'ip') && r === '') ||
      ((page === 'network' || page === 'ping' || page === 'whois') && r === 'network');
    a.classList.toggle('active', on);
  });
  var titles = { '': '概览 - IP 网络工具箱', 'ai': 'AI 检测 - IP 网络工具箱', 'status': '服务状态 - IP 网络工具箱', 'network': '网络检测 - IP 网络工具箱', 'browser': '浏览器检测 - IP 网络工具箱', 'ping': '全球 Ping - IP 网络工具箱', 'whois': 'WHOIS 查询 - IP 网络工具箱', 'ip': 'IP / 域名详情 - IP 网络工具箱' };
  document.title = titles[page] || 'IP 网络工具箱';
  if (page === '') return viewOverview(app, token);
  if (page === 'ai') return viewAI(app, token);
  if (page === 'status') return viewStatus(app, token);
  if (page === 'network') {
    if (parts[1] === 'connectivity') return viewConnectivity(app, token);
    if (parts[1] === 'exits') return viewExits(app, token);
    if (parts[1] === 'dns') return viewDns(app, token);
    if (parts[1] === 'speedtest') return viewSpeedtest(app, token);
    return viewNetwork(app, token);
  }
  if (page === 'ping') return viewPing(app, token);
  if (page === 'whois') return viewWhois(app, token);
  if (page === 'ip') return viewIpDetail(app, token, arg);
  if (page === 'browser') return viewBrowser(app, token);
  app.innerHTML = '<div class="card"><h1>页面不存在</h1><p class="muted">请从顶部导航进入。</p></div>';
}
window.addEventListener('hashchange', render);

/* ---------- 概览 ---------- */

/* ---------- 旧版首页所需数据与工具 ---------- */
var HOME_SITES = [
  { name: '字节跳动', host: 'www.bytedance.com', url: 'https://perfops.byte-test.com/500b-bench.jpg' },
  { name: '淘宝', host: 'www.taobao.com', url: 'https://www.taobao.com/favicon.ico' },
  { name: '微信', host: 'weixin.qq.com', url: 'https://res.wx.qq.com/a/wx_fed/assets/res/NTI4MWU5.ico' },
  { name: 'GitHub', host: 'github.com', url: 'https://github.com/generate_204' },
  { name: 'Cloudflare', host: 'www.cloudflare.com', url: 'https://1.1.1.1/cdn-cgi/trace' },
  { name: 'YouTube', host: 'www.youtube.com', url: 'https://www.youtube.com/generate_204' }
];
/* 分流出口探测：[名称, 方法, 域名或地址]，与旧版 sites.json 一致（50 站） */
var EGRESS_SITES = [
  ['Telegram', 'unsupported', 'web.telegram.org'],
  ['IP.cn', 'ip-text', 'https://my.ip.cn/'],
  ['IP.SB', 'ip-json', 'https://api.ip.sb/jsonip'],
  ['网易', 'netease', ''],
  ['字节跳动', 'bytedance', 'https://perfops.byte-test.com/500b-bench.jpg'],
  ['Cloudflare中国', 'cftrace', 'www.cloudflare-cn.com'],
  ['高通中国', 'cftrace', 'www.qualcomm.cn'],
  ['discord.com', 'cftrace', 'gateway.discord.gg'],
  ['x.com', 'cftrace', 'x.com'],
  ['medium.com', 'cftrace', 'medium.com'],
  ['anthropic.com', 'cftrace', 'anthropic.com'],
  ['claude.ai', 'cftrace', 'claude.ai'],
  ['chatgpt.com', 'cftrace', 'chatgpt.com'],
  ['openai.com', 'cftrace', 'openai.com'],
  ['sora.com', 'cftrace', 'sora.com'],
  ['grok.com', 'cftrace', 'grok.com'],
  ['pixpix.com', 'cftrace', 'pixpix.com'],
  ['perplexity.ai', 'cftrace', 'www.perplexity.ai'],
  ['midjourney.com', 'cftrace', 'midjourney.com'],
  ['coinbase.com', 'cftrace', 'coinbase.com'],
  ['www.okx.com', 'cftrace', 'www.okx.com'],
  ['binance.com', 'cftrace', 'www.binance.com'],
  ['crypto.com', 'cftrace', 'crypto.com'],
  ['zoom.us', 'cftrace', 'zoom.us'],
  ['1password.com', 'cftrace', '1password.com'],
  ['wise.com', 'cftrace', 'wise.com'],
  ['notion.so', 'cftrace', 'notion.so'],
  ['shopify.com', 'cftrace', 'shopify.com'],
  ['godaddy.com', 'cftrace', 'godaddy.com'],
  ['producthunt.com', 'cftrace', 'producthunt.com'],
  ['cloudflare.com', 'cftrace', 'www.cloudflare.com'],
  ['cloudflare cdnjs', 'cftrace', 'cdnjs.cloudflare.com'],
  ['npm registry', 'cftrace', 'registry.npmjs.org'],
  ['kali.download', 'cftrace', 'kali.download'],
  ['unpkg.com', 'cftrace', 'unpkg.com'],
  ['nodejs.org', 'cftrace', 'nodejs.org'],
  ['gitlab.com', 'cftrace', 'gitlab.com'],
  ['crunchyroll.com', 'cftrace', 'crunchyroll.com'],
  ['kraken.com', 'cftrace', 'www.kraken.com'],
  ['bybit.com', 'cftrace', 'www.bybit.com'],
  ['bitget.com', 'cftrace', 'www.bitget.com'],
  ['kucoin.com', 'cftrace', 'www.kucoin.com'],
  ['amazon.com', 'cftrace', 'www.amazon.com'],
  ['ebay.com', 'cftrace', 'www.ebay.com'],
  ['aliexpress.com', 'cftrace', 'www.aliexpress.com'],
  ['temu.com', 'cftrace', 'www.temu.com'],
  ['shein.com', 'cftrace', 'www.shein.com'],
  ['etsy.com', 'cftrace', 'www.etsy.com'],
  ['shopee.com', 'cftrace', 'www.shopee.com'],
  ['lazada.com', 'cftrace', 'www.lazada.com']
];
var HOME_SERVICES = ['9', '4', '10', '5', '0', '19', '15', '1'];
var HOME_STATUS_LABELS = { none: '正常运行', minor: '轻微故障', major: '严重故障', critical: '重大故障', maintenance: '维护中', unknown: '未知' };
function flagImg(code){
  if (!code || !/^[a-z]{2}$/i.test(code)) return '';
  return '<img class="flag" src="https://flagcdn.com/w40/' + code.toLowerCase() + '.png" alt="" loading="lazy" referrerpolicy="no-referrer">';
}
function scoreColor(score){
  if (score >= 80) return 'var(--green)';
  if (score >= 60) return '#d97706';
  return 'var(--red)';
}
function dotsHtml(ms, ok){
  var html = '<span class="dots">';
  var i, cls;
  for (i = 0; i < 8; i++) {
    if (!ok) cls = '';
    else if (ms < 150) cls = 'g';
    else if (ms < 400) cls = (i < 6) ? 'g' : 'y';
    else if (ms < 800) cls = (i < 3) ? 'g' : 'y';
    else cls = (i < 2) ? 'y' : 'r';
    html += '<i class="' + cls + '"></i>';
  }
  return html + '</span>';
}
function probeUrl(url){
  return imgProbe(url, 8000).then(function(r){
    if (r.ok) return r;
    return fetchProbe(url, 8000).then(function(r2){
      if (r2.ok) return r2;
      return imgProbe(url, 8000);
    });
  });
}
function probeRoundsUrl(url, rounds){
  var jobs = [];
  for (var i = 0; i < rounds; i++) jobs.push(probeUrl(url));
  return Promise.all(jobs).then(function(results){
    var oks = results.filter(function(r){ return r.ok; }).map(function(r){ return r.ms; }).sort(function(a, b){ return a - b; });
    if (!oks.length) return { ok: false, ms: -1, success: 0, total: rounds };
    return { ok: true, ms: oks[Math.floor(oks.length / 2)], success: oks.length, total: rounds };
  });
}
function isV4(ip){
  var parts = String(ip || '').split('.');
  if (parts.length !== 4) return false;
  for (var i = 0; i < 4; i++) {
    var p = parts[i];
    if (!p || p.length > 3) return false;
    for (var j = 0; j < p.length; j++) {
      if (p.charAt(j) < '0' || p.charAt(j) > '9') return false;
    }
    if (Number(p) > 255) return false;
  }
  return true;
}
function getDomesticIp(){
  var sources = [
    { url: 'https://necaptcha.nosdn.127.net/ab7f4275c1744aa28e0a8f3a1c58c532.png', header: 'cdn-user-ip' },
    { url: 'https://perfops.byte-test.com/500b-bench.jpg', header: 'x-request-ip' }
  ];
  var chain = Promise.reject(new Error('国内出口未知'));
  sources.forEach(function(source){
    chain = chain.catch(function(){
      var ctrl = new AbortController();
      var timer = setTimeout(function(){ ctrl.abort(); }, 3000);
      return fetch(source.url, { method: 'HEAD', mode: 'cors', credentials: 'omit', redirect: 'error', cache: 'no-store', signal: ctrl.signal }).then(function(res){
        clearTimeout(timer);
        var ip = (res.headers.get(source.header) || '').trim();
        if (!ip || !isV4(ip)) throw new Error('未获取到国内出口 IP');
        return { ip: ip };
      }).catch(function(e){
        clearTimeout(timer);
        throw e;
      });
    });
  });
  return chain;
}
function detectEgressSite(site){
  var method = site[1];
  var value = site[2];
  var timeout = 5000;
  if (method === 'unsupported') return Promise.resolve(null);
  if (method === 'cftrace') {
    return fetch('https://' + value + '/cdn-cgi/trace', { mode: 'cors', cache: 'no-store', signal: AbortSignal.timeout(timeout) }).then(function(res){
      return res.text();
    }).then(function(text){
      var m = text.match(/^ip=(.+)$/m);
      if (!m) throw new Error('未读到出口 IP');
      return { ip: m[1].trim() };
    });
  }
  if (method === 'ip-json') {
    return fetch(value, { cache: 'no-store', signal: AbortSignal.timeout(timeout) }).then(function(res){ return res.json(); }).then(function(d){
      if (!d.ip) throw new Error('未读到出口 IP');
      return { ip: d.ip };
    });
  }
  if (method === 'ip-text') {
    return fetch(value, { cache: 'no-store', signal: AbortSignal.timeout(timeout) }).then(function(res){ return res.text(); }).then(function(text){
      var m = text.match(/((?:\\d{1,3}\\.){3}\\d{1,3})/);
      if (!m) throw new Error('未读到出口 IP');
      return { ip: m[1] };
    });
  }
  if (method === 'netease' || method === 'bytedance') {
    var source = method === 'netease'
      ? { url: 'https://necaptcha.nosdn.127.net/ab7f4275c1744aa28e0a8f3a1c58c532.png', header: 'cdn-user-ip' }
      : { url: 'https://perfops.byte-test.com/500b-bench.jpg', header: 'x-request-ip' };
    return fetch(source.url, { method: 'HEAD', mode: 'cors', credentials: 'omit', redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(timeout) }).then(function(res){
      var ip = (res.headers.get(source.header) || '').trim();
      if (!ip) throw new Error('未读到出口 IP');
      return { ip: ip };
    });
  }
  return Promise.resolve(null);
}
function renderIpCard(el, label, me, health, type, score){
  var badges = '';
  var seen = {};
  function addBadge(text, cls){
    if (seen[text]) return;
    seen[text] = true;
    badges += '<span class="badge ' + cls + '">' + esc(text) + '</span>';
  }
  if (health) {
    if (health.isHosting) addBadge('机房 IP', 'b-blue');
    if (health.isProxy) addBadge('代理', 'b-blue');
    if (health.isVpn) addBadge('VPN', 'b-blue');
    if (health.isTor) addBadge('Tor 出口', 'b-red');
  }
  if (type && type.available) {
    if (type.hosting) addBadge('机房 IP', 'b-blue');
    if (type.mobile) addBadge('移动网络', 'b-blue');
    if (type.proxy) addBadge('代理', 'b-blue');
  }
  var scoreHtml = '';
  if (typeof score === 'number' && isFinite(score)) {
    scoreHtml = '<div class="ip-score"><div class="score-num" style="color:' + scoreColor(score) + '">' + score + '</div><div class="score-label">IP 信誉分</div></div>';
  }
  var place = [me.country, me.region, me.city].filter(Boolean).join(' · ');
  var line2 = [me.isp, me.asn ? 'AS' + me.asn : ''].filter(Boolean).join(' · ');
  el.innerHTML =
    '<div class="eyebrow"><span>' + esc(label) + '</span>' + badges + '</div>' +
    '<div class="ip-card-top"><div class="ip-main">' +
    '<div class="bigip">' + flagImg(me.country_code) + '<a href="#/ip/' + encodeURIComponent(me.ip) + '">' + esc(me.ip) + '</a></div>' +
    '<div class="ip-meta"><p>' + esc(place || '归属信息暂不可用') + '</p>' +
    (line2 ? '<p class="sub">' + esc(line2) + '</p>' : '') + '</div>' +
    '</div>' + scoreHtml + '</div>';
}
function loadExternalCard(token){
  Promise.allSettled([api('/me'), api('/ip/health')]).then(function(results){
    if (token !== viewToken) return;
    var el = document.getElementById('cardExternal');
    if (!el) return;
    var me = results[0].status === 'fulfilled' ? results[0].value : null;
    var health = results[1].status === 'fulfilled' ? results[1].value : null;
    if (!me) {
      el.innerHTML = '<div class="eyebrow"><span>IPv4 · 外部探测</span></div><div class="err">获取当前 IP 失败：' + esc(results[0].reason && results[0].reason.message ? results[0].reason.message : '请刷新重试') + '</div>';
      return;
    }
    var score = health && health.score != null ? health.score : null;
    renderIpCard(el, 'IPv4 · 外部探测', me, health, null, score);
    api('/ip-type/' + encodeURIComponent(me.ip)).then(function(t){
      if (token !== viewToken || !t.available) return;
      renderIpCard(el, 'IPv4 · 外部探测', me, health, t, score);
    }).catch(function(){});
  });
}
function loadDomesticCard(token){
  var el = document.getElementById('cardDomestic');
  if (!el) return;
  getDomesticIp().then(function(d){
    if (token !== viewToken) return;
    function done(geo){
      renderIpCard(el, 'IPv4 · 国内探测', geo, null, null, null);
      api('/ip-type/' + encodeURIComponent(d.ip)).then(function(t){
        if (token !== viewToken || !t.available) return;
        renderIpCard(el, 'IPv4 · 国内探测', geo, null, t, null);
      }).catch(function(){});
    }
    api('/geoip/' + encodeURIComponent(d.ip)).then(function(geo){
      if (token !== viewToken) return;
      done(geo);
    }).catch(function(){
      api('/ip/lookup/' + encodeURIComponent(d.ip)).then(function(data){
        if (token !== viewToken) return;
        done(data.geo || { ip: d.ip });
      }).catch(function(){
        if (token !== viewToken) return;
        done({ ip: d.ip });
      });
    });
  }).catch(function(){
    if (token !== viewToken) return;
    el.innerHTML = '<div class="eyebrow"><span>IPv4 · 国内探测</span></div><div class="err">国内出口未知：目标站点可能限制跨域读取。</div>';
  });
}
function loadHomeConnectivity(token){
  runLimited(HOME_SITES, 6, function(site){
    return probeRoundsUrl(site.url, 3).then(function(r){ return { site: site, r: r }; });
  }).then(function(results){
    if (token !== viewToken) return;
    var box = document.getElementById('connTiles');
    if (!box) return;
    results.sort(function(a, b){
      var l = a.r.ok ? a.r.ms : Infinity;
      var r = b.r.ok ? b.r.ms : Infinity;
      return l - r;
    });
    var html = '';
    results.forEach(function(item){
      html += '<div class="tile"><div class="tile-top"><span class="tile-name">' + iconImg(item.site.host) + '<span>' + esc(item.site.name) + '</span></span>' +
        '<span class="ms ' + msClass(item.r.ok ? item.r.ms : -1) + '">' + msText(item.r.ok ? item.r.ms : -1) + '</span></div>' +
        dotsHtml(item.r.ok ? item.r.ms : -1, item.r.ok) + '</div>';
    });
    box.innerHTML = html;
  });
}
function loadEgress(token){
  var box = document.getElementById('egressBox');
  var foot = document.getElementById('egressFoot');
  if (!box) return;
  runLimited(EGRESS_SITES, 6, function(site){
    return detectEgressSite(site).then(function(r){ return { site: site, r: r }; }).catch(function(){ return { site: site, r: null }; });
  }).then(function(items){
    if (token !== viewToken) return;
    var byIp = {};
    var okCount = 0;
    items.forEach(function(item){
      if (item.r && item.r.ip) {
        okCount++;
        if (!byIp[item.r.ip]) byIp[item.r.ip] = { ip: item.r.ip, count: 0 };
        byIp[item.r.ip].count++;
      }
    });
    var groups = Object.keys(byIp).map(function(ip){ return byIp[ip]; }).sort(function(a, b){ return b.count - a.count; });
    if (!groups.length) {
      box.innerHTML = '<p class="muted">本次未能读取到各站点的出口 IP（可能被浏览器或网络拦截），可直接打开“查看全部”逐站检测。</p>';
      if (foot) foot.textContent = '已读取 0 / ' + EGRESS_SITES.length + ' 个站点的出口';
      return;
    }
    var ips = groups.slice(0, 4).map(function(g){ return g.ip; });
    Promise.allSettled(ips.map(function(ip){ return api('/geoip/' + encodeURIComponent(ip)); })).then(function(geoResults){
      if (token !== viewToken) return;
      var html = '';
      groups.slice(0, 4).forEach(function(g, i){
        var geo = geoResults[i].status === 'fulfilled' ? geoResults[i].value : null;
        html += '<div class="egress-row">' + flagImg(geo && geo.country_code) + '<span class="bigip" style="font-size:19px">' + esc(g.ip) + '</span><span class="muted" style="margin-left:auto">' + g.count + '个站点</span></div>';
      });
      box.innerHTML = html;
      if (foot) foot.textContent = '已读取 ' + okCount + ' / ' + EGRESS_SITES.length + ' 个站点的出口';
    });
  });
}
function loadHomeAI(token){
  runLimited(AI_SITES, 8, function(site){
    return probeSite(site.host).then(function(r){ return { site: site, r: r }; });
  }).then(function(results){
    if (token !== viewToken) return;
    var box = document.getElementById('aiBox');
    if (!box) return;
    results.sort(function(a, b){
      var l = a.r.ok ? a.r.ms : Infinity;
      var r = b.r.ok ? b.r.ms : Infinity;
      return l - r;
    });
    var html = '';
    results.forEach(function(item){
      html += '<div class="ai-row"><a class="nm" href="#/ai">' + iconImg(item.site.host) + '<span>' + esc(item.site.name) + '</span></a>' +
        (item.r.ok ? '<span class="ms-orange">' + item.r.ms + ' ms</span>' : '<span class="muted">不可达</span>') + '</div>';
    });
    box.innerHTML = html;
  });
}
function loadHomeStatus(token){
  runLimited(HOME_SERVICES, 4, function(id){
    var svc = null;
    SERVICES.forEach(function(s){ if (s[0] === id) svc = s; });
    return api('/status/' + encodeURIComponent(id), { timeout: 15000 }).then(function(d){
      return { svc: svc, d: d };
    }).catch(function(){ return { svc: svc, d: null }; });
  }).then(function(results){
    if (token !== viewToken) return;
    var box = document.getElementById('svcBox');
    if (!box) return;
    var html = '';
    results.forEach(function(item){
      if (!item.svc) return;
      var host = '';
      try { host = new URL(item.svc[3]).host; } catch (e) { host = ''; }
      var ind = (item.d && item.d.status && item.d.status.indicator) || 'unknown';
      var label = HOME_STATUS_LABELS[ind] || '未知';
      var cls = ind === 'none' ? 'st-ok' : (ind === 'maintenance' ? 'st-warn' : (ind === 'unknown' ? 'st-unk' : 'st-bad'));
      html += '<div class="svc-row"><a class="nm" href="#/status">' + iconImg(host) + '<span>' + esc(item.svc[1]) + '</span></a><span class="' + cls + '">' + esc(label) + '</span></div>';
    });
    box.innerHTML = html;
  });
}
function loadHomeBrowser(token){
  var box = document.getElementById('browserBox');
  if (!box) return;
  var ua = navigator.userAgent || '';
  var line = (navigator.platform || '') + ' · ' + (navigator.language || '') + ' · ' + (Intl.DateTimeFormat().resolvedOptions().timeZone || '');
  box.innerHTML =
    '<p class="small muted" style="word-break:break-all">' + esc(line) + '</p>' +
    '<p class="small muted" style="word-break:break-all">' + esc(ua) + '</p>' +
    '<div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border);display:flex;flex-wrap:wrap;align-items:center;gap:8px"><span class="muted" style="flex:1">浏览器指纹 · Visitor ID</span><span class="ms" id="homeVisitorId">检测中…</span></div>' +
    '<div style="margin-top:10px;display:flex;flex-wrap:wrap;gap:16px"><a href="#/browser">指纹检测 ›</a><a href="#/browser">环境一致性 ›</a><a href="#/browser">权限与隐私 ›</a></div>';
  sha256Hex(ua + '|' + screen.width + 'x' + screen.height + '|' + (Intl.DateTimeFormat().resolvedOptions().timeZone || '') + '|' + (navigator.language || '')).then(function(h){
    var el = document.getElementById('homeVisitorId');
    if (el && h) el.textContent = h.slice(0, 16);
  });
}
function shortcutLink(href, iconHtml, label, desc){
  return '<a href="' + href + '"><span class="shortcut-icon">' + iconHtml + '</span><span class="shortcut-label"><strong>' + esc(label) + '</strong><span class="shortcut-description">' + esc(desc) + '</span></span><span class="shortcut-arrow">→</span></a>';
}

function featureTile(href, iconHtml, label, color){
  var style = color ? ' style="color:' + color + '"' : '';
  return '<a class="feature-tile" href="' + href + '"><span class="feature-icon"' + style + '>' + iconHtml + '</span><span class="feature-label">' + esc(label) + '</span></a>';
}

function promoLink(href, iconHtml, label, desc, color){
  var style = color ? ' style="color:' + color + '"' : '';
  return '<a class="feature-tile" href="' + href + '" target="_blank" rel="noopener"><span class="feature-icon"' + style + '>' + iconHtml + '</span><span class="feature-label">' + esc(label) + '</span><span class="feature-sub">' + esc(desc) + '</span></a>';
}

function viewOverview(app, token){
  app.innerHTML =
    '<div class="page-head"><h1>网络概览</h1><button class="btn ghost" id="refreshBtn">重新检测</button></div>' +
    '<div class="card"><div class="row"><input id="lookupInput" placeholder="输入 IP 或域名查询，例如 8.8.8.8 / example.com"><button class="btn" id="lookupBtn">查询</button><kbd class="kbd-hint">Ctrl K</kbd></div>' +
    '<p class="muted">查任意 IP 或域名：归属地、ASN、网络拓扑与注册信息。</p></div>' +
    '<div class="ip-grid">' +
      '<div class="card" id="cardDomestic"><div class="skel">正在探测国内出口…</div></div>' +
      '<div class="card" id="cardExternal"><div class="skel">正在获取当前 IP…</div></div>' +
    '</div>' +
    '<div class="card"><div class="row-between"><h3>网络连通性</h3><a class="small muted" href="#/network/connectivity">查看更多 ›</a></div><div class="ping-grid" id="connTiles"><div class="skel">正在探测…</div></div></div>' +
    '<div class="card"><div class="row-between"><h3>网站分流出口</h3><a class="small muted" href="#/network/exits">查看全部 ›</a></div><div id="egressBox"><div class="skel">正在探测出口…</div></div><div class="muted small" id="egressFoot" style="margin-top:8px"></div></div>' +
    '<div class="duo-grid">' +
      '<div class="card"><h3>AI 访问概览</h3><div id="aiBox"><div class="skel">正在探测…</div></div><p class="muted small">显示 HTTP 响应耗时；不可达表示本次探测失败。点击平台查看详情及官网。</p></div>' +
      '<div class="card"><div class="row-between"><h3>服务状态</h3><a class="small muted" href="#/status">全部服务 ›</a></div><div id="svcBox"><div class="skel">正在查询…</div></div><p class="muted small">来自官方状态源，点击服务查看组件与事件。</p></div>' +
    '</div>' +
    '<div class="card"><div class="row-between"><h3>浏览器环境</h3><a class="small muted" href="#/browser">查看完整检测 ›</a></div><div id="browserBox"><div class="skel">正在检测…</div></div></div>' +
    '<div class="card"><h3>热门功能</h3>' +
      '<div class="feature-grid">' +
        featureTile('#/ip/', '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>', 'IP 信息查询', '#38bdf8') +
        featureTile('#/network/dns', '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 5-3.5 8-7 9-3.5-1-7-4-7-9V6l7-3z"/></svg>', 'DNS 泄漏', '#38bdf8') +
        featureTile('#/browser', '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/></svg>', 'WebRTC 泄漏', '#22d3ee') +
        featureTile('#/ai', '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>', '解锁检测', '#94a3b8') +
        featureTile('#/ai', iconImg('chatgpt.com'), 'ChatGPT 检测') +
        featureTile('#/ai', iconImg('claude.ai'), 'Claude 中国用户检测') +
        featureTile('#/network/speedtest', '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 15a8 8 0 1 1 16 0"/><path d="M12 15l4-4"/><path d="M2 15h2M20 15h2"/></svg>', '网站测速', '#38bdf8') +
        featureTile('#/whois', '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 13h6M9 17h6"/></svg>', 'WHOIS', '#a78bfa') +
        featureTile('#/ping', '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="2"/><path d="M12 12l4.5-4.5"/></svg>', '全球 Ping', '#34d399') +
        featureTile('#/browser', '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 11a3 3 0 0 1 3 3c0 2 0 3-1 5"/><path d="M6.5 13a5.5 5.5 0 0 1 11 0c0 1.5-.3 3-1 4.5"/><path d="M3.5 16a8.5 8.5 0 0 1 17 0c0 2.5-.8 4.5-2 6"/></svg>', '浏览器指纹', '#34d399') +
        featureTile('#/browser', '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18z"/></svg>', '环境一致性', '#a78bfa') +
        featureTile('#/status', '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l3 8 4-16 3 8h4"/></svg>', '服务状态', '#34d399') +
      '</div></div>' +
    '<div class="card promo-card"><h3>广告投放</h3>' +
      '<div class="feature-grid promo-grid">' +
        promoLink('https://t.me/eziyuan_1', '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg>', 'TG 频道', '@eziyuan_1', '#229ED9') +
        promoLink('https://blog.t20.de5.net/', '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3a15 15 0 0 1 0 18a15 15 0 0 1 0-18z"/></svg>', '自由论坛', 'blog.t20.de5.net', '#a78bfa') +
        promoLink('https://t.me/jdxxtby_bot', '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg>', '订阅查询机器人', '@jdxxtby_bot', '#229ED9') +
        promoLink('https://t.me/bibipobibibi_bot', '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg>', '私聊 / 投稿 / 广告合作', '@bibipobibibi_bot', '#229ED9') +
      '</div></div>';
  document.getElementById('refreshBtn').addEventListener('click', function(){ render(); });
  var lookupInput = document.getElementById('lookupInput');
  function lookupGo(){ var v = lookupInput.value.trim(); if (!v) return; location.hash = '#/ip/' + encodeURIComponent(v); }
  document.getElementById('lookupBtn').addEventListener('click', lookupGo);
  lookupInput.addEventListener('keydown', function(e){ if (e.key === 'Enter') lookupGo(); });
  if (!window.__oneIpKbd) { window.__oneIpKbd = true; document.addEventListener('keydown', function(e){ if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'K')) { var el = document.getElementById('lookupInput'); if (el) { e.preventDefault(); el.focus(); el.select(); } } }); }
  loadExternalCard(token);
  loadDomesticCard(token);
  loadHomeConnectivity(token);
  loadEgress(token);
  loadHomeAI(token);
  loadHomeStatus(token);
  loadHomeBrowser(token);
}

/* ---------- AI 检测 ---------- */
function viewAI(app, token){
  app.innerHTML =
    '<h1>AI 服务连通检测</h1>' +
    '<div class="note">浏览器端探测：用图标加载 + no-cors 请求双信号判定可达，不要求读取跨域响应；耗时为浏览器请求耗时，不是 ICMP 延迟。机房出口可能被个别站点限流，失败不代表站点宕机。</div>' +
    '<div id="aiBox"><div class="skel">正在探测 8 个 AI 站点…</div></div>';
  runLimited(AI_SITES, 8, function(site){
    return probeSite(site.host).then(function(r){ return { site: site, r: r }; });
  }).then(function(results){
    if (token !== viewToken) return;
    var box = document.getElementById('aiBox');
    if (!box) return;
    var ok = results.filter(function(x){ return x.r.ok; }).length;
    var html = '<div class="card"><h3>连通 ' + ok + ' / ' + results.length + '</h3><table><tbody>';
    results.forEach(function(item){
      html += '<tr><td>' + iconImg(item.site.host) + esc(item.site.name) + '</td>' +
        '<td>' + esc(item.site.host) + '</td>' +
        '<td><span class="ms ' + msClass(item.r.ok ? item.r.ms : -1) + '">' + msText(item.r.ok ? item.r.ms : -1) + '</span></td>' +
        '<td>' + (item.r.ok ? '<span class="badge b-green">可达</span>' : '<span class="badge b-gray">未连通</span>') + '</td></tr>';
    });
    html += '</tbody></table></div>' +
      '<div class="card"><h3>怎么看这个结果</h3><p class="muted">“可达”表示浏览器能打开该站（图标或页面资源有响应）；“未连通”可能是出口 IP 被站点限流、站点拒绝机房 IP，或真的打不开。换个网络或过几分钟重试，经常能恢复。</p></div>';
    box.innerHTML = html;
  });
}

/* ---------- 服务状态 ---------- */
var STATUS_LABELS = { none: '正常运行', minor: '轻微故障', major: '严重故障', critical: '重大故障', maintenance: '维护中', unknown: '未知' };
function viewStatus(app, token){
  app.innerHTML =
    '<h1>服务状态</h1>' +
    '<p class="muted">聚合各平台官方状态源实时查询。官方状态页是唯一权威来源，本页结果仅供参考。</p>' +
    '<div id="statusSummary"><div class="skel">正在查询 44 个服务…</div></div>' +
    '<div id="statusList"></div>';
  var groups = {};
  SERVICES.forEach(function(s){
    if (!groups[s[2]]) groups[s[2]] = [];
    groups[s[2]].push(s);
  });
  var html = '';
  Object.keys(groups).forEach(function(g){
    html += '<div class="card"><h3>' + esc(g) + '</h3>';
    groups[g].forEach(function(s){
      var host = '';
      try { host = new URL(s[3]).host; } catch (e) { host = ''; }
      html += '<div id="svc-' + esc(s[0]) + '" style="padding:8px 0;border-bottom:1px solid var(--border)">' +
        '<span class="dot gr"></span>' + iconImg(host) + '<b>' + esc(s[1]) + '</b> <span class="muted">检测中…</span></div>';
    });
    html += '</div>';
  });
  document.getElementById('statusList').innerHTML = html;
  var counts = { none: 0, minor: 0, major: 0, critical: 0, maintenance: 0, unknown: 0, done: 0 };
  function updateSummary(){
    document.getElementById('statusSummary').innerHTML =
      '<div class="card"><span class="badge b-green">正常运行 ' + counts.none + '</span>' +
      '<span class="badge b-red">轻微故障 ' + counts.minor + '</span>' +
      '<span class="badge b-red">严重故障 ' + counts.major + '</span>' +
      '<span class="badge b-red">重大故障 ' + counts.critical + '</span>' +
      '<span class="badge b-yellow">维护中 ' + counts.maintenance + '</span>' +
      '<span class="badge b-gray">未知 ' + counts.unknown + '</span>' +
      '<span class="muted">已完成 ' + counts.done + ' / ' + SERVICES.length + '</span></div>';
  }
  updateSummary();
  runLimited(SERVICES, 6, function(s){
    return api('/status/' + encodeURIComponent(s[0]), { timeout: 15000 }).then(function(data){
      return { s: s, data: data };
    }).catch(function(e){
      return { s: s, error: e };
    });
  }).then(function(results){
    if (token !== viewToken) return;
    results.forEach(function(item){
      var row = document.getElementById('svc-' + item.s[0]);
      if (!row) return;
      var host = '';
      try { host = new URL(item.s[3]).host; } catch (e) { host = ''; }
      if (item.error) {
        counts.unknown++; counts.done++;
        row.innerHTML = '<span class="dot gr"></span>' + iconImg(host) + '<b>' + esc(item.s[1]) + '</b> <span class="badge b-gray">未知</span> <span class="muted">查询失败</span> <a href="' + esc(item.s[3]) + '" target="_blank" rel="noopener">官方状态页 ↗</a>';
        return;
      }
      var d = item.data;
      var ind = (d.status && d.status.indicator) || 'unknown';
      counts[ind] = (counts[ind] || 0) + 1;
      counts.done++;
      var dot = ind === 'none' ? 'g' : (ind === 'unknown' ? 'gr' : (ind === 'maintenance' ? 'y' : 'r'));
      var label = STATUS_LABELS[ind] || '未知';
      var badge = ind === 'none' ? 'b-green' : (ind === 'unknown' ? 'b-gray' : (ind === 'maintenance' ? 'b-yellow' : 'b-red'));
      var desc = d.status && d.status.description ? ' — ' + esc(d.status.description) : '';
      var incidents = '';
      if (d.incidents && d.incidents.length) {
        incidents = '<div class="muted" style="margin:6px 0 0 16px">' + d.incidents.slice(0, 3).map(function(i){
          return '• ' + esc(i.title || i.name || '事件') + (i.status ? '（' + esc(i.status) + '）' : '');
        }).join('<br>') + '</div>';
      }
      row.innerHTML = '<span class="dot ' + dot + '"></span>' + iconImg(host) + '<b>' + esc(item.s[1]) + '</b> <span class="badge ' + badge + '">' + esc(label) + '</span><span class="muted">' + desc + '</span> <a href="' + esc(item.s[3]) + '" target="_blank" rel="noopener">官方状态页 ↗</a>' + incidents;
    });
    if (token === viewToken) updateSummary();
  });
}

/* ---------- 网络检测（入口） ---------- */
function viewNetwork(app, token){
  app.innerHTML =
    '<h1>网络检测</h1>' +
    '<div class="grid">' +
    '<div class="card"><h3>网络连通性</h3><p class="muted">对常用站点做 3 轮浏览器端探测，取延迟中位数，判断当前网络到各站点的连通情况。</p><a class="btn" href="#/network/connectivity">开始检测</a></div>' +
    '<div class="card"><h3>网站分流出口</h3><p class="muted">50 个站点分组探测，看当前出口 IP 能打开哪些站、被哪些站拦截。</p><a class="btn" href="#/network/exits">开始检测</a></div>' +
    '<div class="card"><h3>DNS 出口</h3><p class="muted">通过公开 DoH 解析器（Cloudflare / Google / Quad9）测试 DNS 解析，查指定域名记录。</p><a class="btn" href="#/network/dns">进入</a></div>' +
    '<div class="card"><h3>测速</h3><p class="muted">测浏览器到本站边缘节点的延迟、下载与上传速度。</p><a class="btn" href="#/network/speedtest">开始测速</a></div>' +
    '<div class="card"><h3>全球 Ping</h3><p class="muted">从全球节点向目标域名或 IP 发起 Ping / HTTPS 探测（需先完成一次轻量验证）。</p><a class="btn" href="#/ping">进入</a></div>' +
    '<div class="card"><h3>WHOIS 查询</h3><p class="muted">查域名或 IP 的注册信息（RDAP），附带子域名枚举。</p><a class="btn" href="#/whois">进入</a></div>' +
    '</div>';
}

/* ---------- 网络连通性 ---------- */
function viewConnectivity(app, token){
  app.innerHTML =
    '<h1>网络连通性</h1>' +
    '<div class="note">浏览器端探测：每个站点发 3 轮请求（图标加载 + no-cors 请求双信号），取成功请求的延迟中位数；不要求读取跨域响应。延迟为浏览器请求耗时，不是 ICMP 延迟。机房出口可能被部分站点限流，个别失败不代表站点宕机。</div>' +
    '<div class="row" style="margin-bottom:12px"><button class="btn" id="reProbe">重新检测</button><span class="muted" id="connProgress">检测中…</span></div>' +
    '<div class="card"><table><thead><tr><th>站点</th><th>延迟（中位数）</th><th>成功轮次</th><th>状态</th></tr></thead><tbody id="connBody"></tbody></table></div>';
  var tbody = document.getElementById('connBody');
  function run(){
    var done = 0;
    document.getElementById('connProgress').textContent = '检测中… 0 / ' + CONNECTIVITY_SITES.length;
    tbody.innerHTML = CONNECTIVITY_SITES.map(function(s){
      return '<tr id="conn-' + esc(s.host) + '"><td>' + iconImg(s.host) + esc(s.name) + '<br><span class="muted">' + esc(s.host) + '</span></td><td colspan="3" class="muted">检测中…</td></tr>';
    }).join('');
    runLimited(CONNECTIVITY_SITES, 4, function(site){
      return probeRounds(site.host, 3).then(function(r){ return { site: site, r: r }; });
    }).then(function(results){
      results.forEach(function(item){
        if (token !== viewToken) return;
        var row = document.getElementById('conn-' + item.site.host);
        if (!row) return;
        row.innerHTML = '<td>' + iconImg(item.site.host) + esc(item.site.name) + '<br><span class="muted">' + esc(item.site.host) + '</span></td>' +
          '<td><span class="ms ' + msClass(item.r.ok ? item.r.ms : -1) + '">' + msText(item.r.ok ? item.r.ms : -1) + '</span></td>' +
          '<td>' + item.r.success + ' / ' + item.r.total + '</td>' +
          '<td>' + (item.r.ok ? '<span class="badge b-green">连通</span>' : '<span class="badge b-gray">未连通</span>') + '</td>';
        done++;
        var p = document.getElementById('connProgress');
        if (p) p.textContent = '已完成 ' + done + ' / ' + CONNECTIVITY_SITES.length;
      });
    });
  }
  document.getElementById('reProbe').addEventListener('click', run);
  run();
}

/* ---------- 网站分流出口 ---------- */
function viewExits(app, token){
  app.innerHTML =
    '<h1>网站分流出口</h1>' +
    '<div class="note">浏览器端探测：逐站用图标加载 + no-cors 请求双信号判定可达，失败自动重试一次；不要求读取跨域响应。延迟为浏览器请求耗时，不是 ICMP 延迟。机房出口被部分站点限流是正常现象，未连通不代表站点宕机。</div>' +
    '<div class="row" style="margin-bottom:12px"><button class="btn" id="reProbe">重新检测</button><span class="muted" id="exitProgress">检测中…</span></div>' +
    '<div id="exitBox"></div>';
  var allSites = [];
  EXIT_GROUPS.forEach(function(g){
    g.sites.forEach(function(s){ allSites.push({ group: g.name, name: s[0], host: s[1] }); });
  });
  var box = document.getElementById('exitBox');
  function buildSkeleton(){
    box.innerHTML = EXIT_GROUPS.map(function(g){
      return '<div class="card"><h3>' + esc(g.name) + ' <span class="muted" id="grp-' + esc(g.name) + '">检测中…</span></h3><table><tbody>' +
        g.sites.map(function(s){
          return '<tr id="exit-' + esc(s[1]) + '"><td>' + iconImg(s[1]) + esc(s[0]) + '<br><span class="muted">' + esc(s[1]) + '</span></td><td class="muted">检测中…</td></tr>';
        }).join('') + '</tbody></table></div>';
    }).join('');
  }
  buildSkeleton();
  var results = {};
  function paint(){
    var ok = 0;
    EXIT_GROUPS.forEach(function(g){
      var gok = 0;
      g.sites.forEach(function(s){ if (results[s[1]] && results[s[1]].ok) gok++; });
      var el = document.getElementById('grp-' + g.name);
      if (el) el.textContent = gok + ' / ' + g.sites.length;
    });
    Object.keys(results).forEach(function(h){ if (results[h].ok) ok++; });
    var p = document.getElementById('exitProgress');
    if (p) p.textContent = '已完成 ' + Object.keys(results).length + ' / ' + allSites.length + '，可达 ' + ok + ' 个';
  }
  function run(){
    results = {};
    paint();
    runLimited(allSites, 8, function(site){
      return probeSite(site.host).then(function(r){ return { site: site, r: r }; });
    }).then(function(items){
      items.forEach(function(item){
        if (token !== viewToken) return;
        results[item.site.host] = item.r;
        var row = document.getElementById('exit-' + item.site.host);
        if (row) {
          row.innerHTML = '<td>' + iconImg(item.site.host) + esc(item.site.name) + '<br><span class="muted">' + esc(item.site.host) + '</span></td>' +
            '<td><span class="ms ' + msClass(item.r.ok ? item.r.ms : -1) + '">' + msText(item.r.ok ? item.r.ms : -1) + '</span> ' +
            (item.r.ok ? '<span class="badge b-green">可达</span>' : '<span class="badge b-gray">未连通</span>') + '</td>';
        }
        paint();
      });
    });
  }
  document.getElementById('reProbe').addEventListener('click', function(){
    buildSkeleton();
    run();
  });
  run();
}

/* ---------- DNS 出口 ---------- */
function viewDns(app, token){
  app.innerHTML =
    '<h1>DNS 出口</h1>' +
    '<div class="note">浏览器无法直接看到系统 DNS 服务器，这里通过公开 DoH 解析器（Cloudflare / Google / Quad9）测试解析结果，顺带测试本站的 DNS 查询接口。下面的解析在本站边缘节点完成，结果以返回的解析器地址为准。</div>' +
    '<div class="card"><h3>解析器对比（A 记录 · www.google.com）</h3><div id="dohBox"><div class="skel">正在测试 3 个解析器…</div></div></div>' +
    '<div class="card"><h3>DNS 查询</h3>' +
    '<div class="row"><input id="dnsDomain" placeholder="输入域名，例如 example.com"><select id="dnsType" style="flex:0 0 110px"><option>A</option><option>AAAA</option><option>MX</option><option>TXT</option><option>NS</option><option>CNAME</option><option>SOA</option><option>PTR</option><option>SRV</option><option>CAA</option><option>HTTPS</option></select>' +
    '<select id="dnsResolver" style="flex:0 0 150px"><option value="cf">Cloudflare</option><option value="google">Google</option><option value="quad9">Quad9</option></select>' +
    '<button class="btn" id="dnsBtn">查询</button></div>' +
    '<div id="dnsResult"></div></div>';
  var resolvers = [['cf', 'Cloudflare'], ['google', 'Google'], ['quad9', 'Quad9']];
  runLimited(resolvers, 3, function(r){
    var t0 = performance.now();
    return api('/dns/lookup/www.google.com?type=A&resolver=' + r[0]).then(function(d){
      return { name: r[1], d: d, ms: Math.round(performance.now() - t0) };
    }).catch(function(e){ return { name: r[1], error: e }; });
  }).then(function(items){
    if (token !== viewToken) return;
    var box = document.getElementById('dohBox');
    if (!box) return;
    var html = '<table><thead><tr><th>解析器</th><th>耗时</th><th>解析结果</th></tr></thead><tbody>';
    items.forEach(function(it){
      if (it.error) {
        html += '<tr><td>' + esc(it.name) + '</td><td>—</td><td><span class="badge b-gray">失败</span> <span class="muted">' + esc(it.error.message || '查询失败') + '</span></td></tr>';
      } else {
        var answers = (it.d.Answer || []).map(function(a){ return esc(a.data); }).join('<br>');
        html += '<tr><td>' + esc(it.name) + '</td><td><span class="ms ' + msClass(it.ms) + '">' + it.ms + ' ms</span></td><td>' + (answers || '<span class="muted">无记录</span>') + '</td></tr>';
      }
    });
    html += '</tbody></table>';
    box.innerHTML = html;
  });
  function queryDns(){
    var domain = document.getElementById('dnsDomain').value.trim();
    var type = document.getElementById('dnsType').value;
    var resolver = document.getElementById('dnsResolver').value;
    var out = document.getElementById('dnsResult');
    if (!domain) { out.innerHTML = '<div class="err">请先输入域名。</div>'; return; }
    out.innerHTML = '<div class="skel">查询中…</div>';
    api('/dns/lookup/' + encodeURIComponent(domain) + '?type=' + encodeURIComponent(type) + '&resolver=' + encodeURIComponent(resolver)).then(function(d){
      if (token !== viewToken) return;
      var html = '';
      if (d.Status !== 0) html += '<div class="err">解析失败：' + esc(d.Comment || ('DNS 状态码 ' + d.Status)) + '</div>';
      var rows = (d.Answer || []).map(function(a){
        return '<tr><td>' + esc(a.name) + '</td><td>' + esc(a.type) + '</td><td>' + esc(a.TTL) + '</td><td>' + esc(a.data) + '</td></tr>';
      }).join('');
      if (rows) html += '<table style="margin-top:10px"><thead><tr><th>名称</th><th>类型</th><th>TTL</th><th>值</th></tr></thead><tbody>' + rows + '</tbody></table>';
      else if (d.Status === 0) html += '<p class="muted" style="margin-top:10px">该类型下无记录。</p>';
      out.innerHTML = html;
    }).catch(function(e){
      if (token !== viewToken) return;
      out.innerHTML = '<div class="err">查询失败：' + esc(e.message || '请重试') + '</div>';
    });
  }
  document.getElementById('dnsBtn').addEventListener('click', queryDns);
  document.getElementById('dnsDomain').addEventListener('keydown', function(e){ if (e.key === 'Enter') queryDns(); });
}

/* ---------- 测速 ---------- */
function viewSpeedtest(app, token){
  app.innerHTML =
    '<h1>测速</h1>' +
    '<div class="note">测的是浏览器到本站边缘节点（Cloudflare）的速度，反映你到最近边缘节点的网络质量，不等于到某个具体网站的速度。</div>' +
    '<div class="row" style="margin-bottom:12px"><button class="btn" id="speedBtn">开始测速</button><span class="muted" id="speedStatus">点击开始，依次测延迟、下载、上传。</span></div>' +
    '<div class="grid">' +
    '<div class="card"><h3>延迟</h3><div class="bigip" id="latVal" style="font-size:28px">—</div><p class="muted" id="latNote">10 次请求取最小值</p></div>' +
    '<div class="card"><h3>下载速度</h3><div class="bigip" id="dlVal" style="font-size:28px">—</div><div class="bar"><i id="dlBar" style="width:0%"></i></div><p class="muted" id="dlNote">下载 5 MB 数据</p></div>' +
    '<div class="card"><h3>上传速度</h3><div class="bigip" id="ulVal" style="font-size:28px">—</div><div class="bar"><i id="ulBar" style="width:0%"></i></div><p class="muted" id="ulNote">上传 2 MB 数据</p></div>' +
    '</div>';
  function fmtMbps(bytes, ms){
    if (!ms) return '—';
    return (bytes * 8 / (ms / 1000) / 1000000).toFixed(1) + ' Mbps';
  }
  document.getElementById('speedBtn').addEventListener('click', function(){
    var btn = this;
    btn.disabled = true;
    var status = document.getElementById('speedStatus');
    status.textContent = '正在测延迟…';
    var latTimes = [];
    var latChain = Promise.resolve();
    for (var i = 0; i < 10; i++) {
      latChain = latChain.then(function(){
        var t0 = performance.now();
        return fetch('/api/me', { cache: 'no-store' }).then(function(){ latTimes.push(performance.now() - t0); }).catch(function(){});
      });
    }
    latChain.then(function(){
      if (token !== viewToken) return;
      if (latTimes.length) {
        var min = Math.min.apply(null, latTimes);
        document.getElementById('latVal').textContent = Math.round(min) + ' ms';
        document.getElementById('latNote').textContent = '10 次请求，成功 ' + latTimes.length + ' 次，取最小值';
      } else {
        document.getElementById('latVal').textContent = '失败';
      }
      status.textContent = '正在测下载速度…';
      var t0 = performance.now();
      return fetch('/api/speedtest?bytes=5242880', { cache: 'no-store' }).then(function(res){
        return res.arrayBuffer().then(function(buf){
          var ms = performance.now() - t0;
          document.getElementById('dlVal').textContent = fmtMbps(buf.byteLength, ms);
          document.getElementById('dlBar').style.width = Math.min(100, buf.byteLength * 8 / (ms / 1000) / 1000000) + '%';
          document.getElementById('dlNote').textContent = '下载 ' + (buf.byteLength / 1048576).toFixed(1) + ' MB，用时 ' + (ms / 1000).toFixed(1) + ' 秒';
        });
      }).catch(function(){
        document.getElementById('dlVal').textContent = '失败';
      });
    }).then(function(){
      if (token !== viewToken) return;
      status.textContent = '正在测上传速度…';
      var payload = new Uint8Array(2097152).fill(120);
      var t0 = performance.now();
      return fetch('/api/speedtest', { method: 'POST', body: payload }).then(function(res){
        return res.json().then(function(d){
          var ms = performance.now() - t0;
          document.getElementById('ulVal').textContent = fmtMbps(d.received || payload.length, ms);
          document.getElementById('ulBar').style.width = Math.min(100, (d.received || 0) * 8 / (ms / 1000) / 1000000) + '%';
          document.getElementById('ulNote').textContent = '上传 ' + ((d.received || 0) / 1048576).toFixed(1) + ' MB，用时 ' + (ms / 1000).toFixed(1) + ' 秒';
        });
      }).catch(function(){
        document.getElementById('ulVal').textContent = '失败';
      });
    }).then(function(){
      if (token !== viewToken) return;
      status.textContent = '测速完成。';
      btn.disabled = false;
    });
  });
}

/* ---------- 工作量证明（替代 Turnstile） ---------- */
/* ch 为后端 /browser/challenges 返回的 challenge 对象：{ nonce, difficulty, expiresIn }。
   找一个数字答案 answer，使得 sha256(nonce + ':' + answer) 以 difficulty 个 0 开头。 */
function solvePow(ch){
  var nonce = ch.nonce;
  var difficulty = ch.difficulty || 2;
  var prefix = '';
  for (var i = 0; i < difficulty; i++) prefix += '0';
  var answer = 0;
  if (!window.crypto || !crypto.subtle) return Promise.reject(new Error('当前浏览器不支持 WebCrypto，无法完成验证'));
  function step(){
    return new Promise(function(resolve, reject){
      var batch = 0;
      function tick(){
        var msg = nonce + ':' + answer;
        crypto.subtle.digest('SHA-256', new TextEncoder().encode(msg)).then(function(buf){
          var hex = Array.from(new Uint8Array(buf)).map(function(b){ return b.toString(16).padStart(2, '0'); }).join('');
          if (hex.slice(0, difficulty) === prefix) { resolve({ answer: String(answer), hash: hex }); return; }
          answer++;
          if (answer > 2000000) { reject(new Error('验证计算超时，请重试')); return; }
          batch++;
          if (batch % 200 === 0) { setTimeout(tick, 0); return; }
          tick();
        }).catch(reject);
      }
      tick();
    });
  }
  return step();
}

/* ---------- 全球 Ping ---------- */
function viewPing(app, token){
  app.innerHTML =
    '<h1>全球 Ping</h1>' +
    '<div class="note">从 Globalping 全球节点向目标发起探测。开始前需完成一次轻量工作量证明验证（浏览器本地算几毫秒，替代图形验证码），用于防滥用。</div>' +
    '<div class="card"><div class="row"><input id="pingTarget" placeholder="输入域名或 IP，例如 8.8.8.8" value="8.8.8.8">' +
    '<select id="pingType" style="flex:0 0 130px"><option value="icmp">ICMP Ping</option><option value="http">HTTP</option></select>' +
    '<button class="btn" id="pingBtn">开始测量</button></div>' +
    '<p class="muted" id="pingStatus">节点列表加载中…</p>' +
    '<div id="pingNodes" style="margin-top:10px"></div></div>' +
    '<div id="pingResult"></div>';
  var selected = null;
  api('/ping/nodes').then(function(nodes){
    if (token !== viewToken) return;
    selected = new Set(nodes.map(function(n){ return n.id; }));
    var byContinent = {};
    nodes.forEach(function(n){
      if (!byContinent[n.continent]) byContinent[n.continent] = [];
      byContinent[n.continent].push(n);
    });
    var html = '';
    Object.keys(byContinent).forEach(function(c){
      html += '<p><b>' + esc(c) + '</b><br>' + byContinent[c].map(function(n){
        return '<span class="chip on" data-node="' + esc(n.id) + '">' + esc(n.name) + '</span>';
      }).join('') + '</p>';
    });
    html += '<p class="muted">默认全选 ' + nodes.length + ' 个节点；点一下可取消/恢复。测量最多用 50 个节点。</p>';
    document.getElementById('pingNodes').innerHTML = html;
    document.getElementById('pingStatus').textContent = '已加载 ' + nodes.length + ' 个节点。';
    document.querySelectorAll('#pingNodes .chip').forEach(function(chip){
      chip.addEventListener('click', function(){
        var id = chip.getAttribute('data-node');
        if (selected.has(id)) { selected.delete(id); chip.classList.remove('on'); }
        else { selected.add(id); chip.classList.add('on'); }
      });
    });
  }).catch(function(e){
    if (token !== viewToken) return;
    document.getElementById('pingStatus').textContent = '节点列表加载失败：' + (e.message || '请刷新重试');
  });
  document.getElementById('pingBtn').addEventListener('click', function(){
    var target = document.getElementById('pingTarget').value.trim();
    var type = document.getElementById('pingType').value;
    var out = document.getElementById('pingResult');
    var status = document.getElementById('pingStatus');
    if (!target) { out.innerHTML = '<div class="err">请先输入域名或 IP。</div>'; return; }
    if (!selected || !selected.size) { out.innerHTML = '<div class="err">请至少选择一个节点。</div>'; return; }
    out.innerHTML = '<div class="skel">正在验证…</div>';
    status.textContent = '正在完成验证（本地计算）…';
    api('/browser/challenges').then(function(ch){
      var c = ch.challenge;
      return solvePow(c).then(function(solution){
        return { provider: 'pow', challenge: c.nonce, answer: solution.answer };
      });
    }).then(function(verification){
      status.textContent = '验证通过，正在发起测量…';
      return api('/ping/start', {
        method: 'POST',
        body: { target: target, verification: verification, options: { type: type, locations: Array.from(selected).slice(0, 50), packets: 3 } }
      });
    }).then(function(start){
      status.textContent = '测量进行中，结果陆续返回…';
      var tries = 0;
      function poll(){
        if (token !== viewToken) return;
        api('/ping/result/' + encodeURIComponent(start.id)).then(function(data){
          var results = data.results || [];
          var html = '<div class="card"><h3>测量结果（' + results.length + ' 个节点已返回）</h3><table><thead><tr><th>节点</th><th>平均延迟</th><th>最小 / 最大</th><th>丢包</th><th>状态</th></tr></thead><tbody>';
          results.forEach(function(r){
            var timings = (r.timings || []).filter(function(t){ return typeof t === 'number'; });
            var avg = timings.length ? Math.round(timings.reduce(function(a, b){ return a + b; }, 0) / timings.length) : null;
            var min = timings.length ? Math.round(Math.min.apply(null, timings)) : null;
            var max = timings.length ? Math.round(Math.max.apply(null, timings)) : null;
            html += '<tr><td>' + esc(r.location || r.id || '—') + '</td>' +
              '<td><span class="ms ' + msClass(avg == null ? -1 : avg) + '">' + msText(avg == null ? -1 : avg) + '</span></td>' +
              '<td>' + (min == null ? '—' : min + ' / ' + max + ' ms') + '</td>' +
              '<td>' + esc(r.packetLoss == null ? '—' : Math.round(r.packetLoss * 100) + '%') + '</td>' +
              '<td>' + (r.status === 'finished' ? '<span class="badge b-green">完成</span>' : '<span class="badge b-yellow">' + esc(r.status || '进行中') + '</span>') + '</td></tr>';
          });
          html += '</tbody></table></div>';
          out.innerHTML = html;
          if (data.status === 'finished' || tries >= 45) {
            status.textContent = data.status === 'finished' ? '测量完成。' : '部分节点未在限时内返回。';
            return;
          }
          tries++;
          setTimeout(poll, 2000);
        }).catch(function(e){
          out.innerHTML = '<div class="err">获取结果失败：' + esc(e.message || '请重试') + '</div>';
        });
      }
      poll();
    }).catch(function(e){
      if (token !== viewToken) return;
      out.innerHTML = '<div class="err">发起测量失败：' + esc(e.message || '请重试') + '</div>';
      status.textContent = '测量未开始。';
    });
  });
}

/* ---------- WHOIS 查询 ---------- */
function viewWhois(app, token){
  app.innerHTML =
    '<h1>WHOIS 查询</h1>' +
    '<p class="muted">查域名或 IP 的注册信息（RDAP 数据源）。</p>' +
    '<div class="card"><div class="row"><input id="whoisInput" placeholder="输入域名或 IP，例如 example.com / 8.8.8.8"><button class="btn" id="whoisBtn">查询</button></div>' +
    '<div id="whoisOut"></div></div>' +
    '<div class="card"><h3>子域名枚举</h3><div class="row"><input id="subInput" placeholder="输入域名，例如 example.com"><button class="btn ghost" id="subBtn">查询子域名</button></div>' +
    '<p class="muted">通过证书透明度日志（crt.sh）枚举公开子域名。</p><div id="subOut"></div></div>';
  function doWhois(){
    var q = document.getElementById('whoisInput').value.trim();
    var out = document.getElementById('whoisOut');
    if (!q) { out.innerHTML = '<div class="err">请先输入域名或 IP。</div>'; return; }
    out.innerHTML = '<div class="skel">查询中…</div>';
    api('/whois/lookup/' + encodeURIComponent(q)).then(function(d){
      if (token !== viewToken) return;
      var data = d.data || {};
      var events = {};
      (data.events || []).forEach(function(e){ events[e.eventAction] = e.eventDate; });
      var registrar = '—';
      (data.entities || []).forEach(function(ent){
        if ((ent.roles || []).indexOf('registrar') >= 0 && ent.vcardArray) {
          (ent.vcardArray[1] || []).forEach(function(f){
            if (f[0] === 'fn') registrar = f[3];
          });
        }
      });
      var ns = (data.nameservers || []).map(function(n){ return esc(n.ldhName || n.objectClassName || ''); }).join('<br>');
      out.innerHTML =
        '<dl class="kv" style="margin-top:12px">' +
        '<dt>对象</dt><dd>' + esc(data.ldhName || data.handle || q) + '</dd>' +
        '<dt>注册商</dt><dd>' + esc(registrar) + '</dd>' +
        '<dt>注册时间</dt><dd>' + esc(events.registration || '—') + '</dd>' +
        '<dt>到期时间</dt><dd>' + esc(events.expiration || '—') + '</dd>' +
        '<dt>最后变更</dt><dd>' + esc(events['last changed'] || '—') + '</dd>' +
        '<dt>状态</dt><dd>' + esc((data.status || []).join(', ') || '—') + '</dd>' +
        '<dt>DNS 服务器</dt><dd>' + (ns || '—') + '</dd>' +
        '</dl>' +
        '<details><summary class="muted">查看原始 JSON</summary><pre>' + esc(JSON.stringify(data, null, 2)) + '</pre></details>';
    }).catch(function(e){
      if (token !== viewToken) return;
      out.innerHTML = '<div class="err">查询失败：' + esc(e.message || '请重试') + '</div>';
    });
  }
  document.getElementById('whoisBtn').addEventListener('click', doWhois);
  document.getElementById('whoisInput').addEventListener('keydown', function(e){ if (e.key === 'Enter') doWhois(); });
  document.getElementById('subBtn').addEventListener('click', function(){
    var q = document.getElementById('subInput').value.trim();
    var out = document.getElementById('subOut');
    if (!q) { out.innerHTML = '<div class="err">请先输入域名。</div>'; return; }
    out.innerHTML = '<div class="skel">查询中…</div>';
    api('/subdomains/' + encodeURIComponent(q)).then(function(d){
      if (token !== viewToken) return;
      var subs = d.subdomains || [];
      out.innerHTML = subs.length
        ? '<p style="margin-top:10px">找到 ' + subs.length + ' 个子域名：</p><p>' + subs.map(function(s){ return '<span class="badge b-blue">' + esc(s) + '</span>'; }).join('') + '</p>'
        : '<p class="muted" style="margin-top:10px">未找到公开子域名。</p>';
    }).catch(function(e){
      if (token !== viewToken) return;
      out.innerHTML = '<div class="err">查询失败：' + esc(e.message || '请重试') + '</div>';
    });
  });
}

/* ---------- IP 详情 ---------- */
function isIpLike(v){
  return /^(\\d{1,3}\\.){3}\\d{1,3}$/.test(v) || /^[0-9a-fA-F:]+$/.test(v) && v.indexOf(':') >= 0;
}
function viewIpDetail(app, token, arg){
  app.innerHTML =
    '<h1>IP / 域名详情</h1>' +
    '<div class="card"><div class="row"><input id="ipInput" placeholder="输入 IP 或域名" value="' + esc(arg) + '"><button class="btn" id="ipBtn">查询</button></div></div>' +
    '<div id="ipBox">' + (arg ? '<div class="skel">正在查询 ' + esc(arg) + '…</div>' : '<p class="muted">输入一个 IP 或域名查看归属地、ASN、网络拓扑与注册信息。</p>') + '</div>';
  function go(){
    var v = document.getElementById('ipInput').value.trim();
    if (v) location.hash = '#/ip/' + encodeURIComponent(v);
  }
  document.getElementById('ipBtn').addEventListener('click', go);
  document.getElementById('ipInput').addEventListener('keydown', function(e){ if (e.key === 'Enter') go(); });
  if (!arg) return;
  var target = Promise.resolve(arg);
  if (!isIpLike(arg)) {
    target = api('/dns/lookup/' + encodeURIComponent(arg) + '?type=A').then(function(d){
      var a = (d.Answer || []).find(function(x){ return x.type === 1; });
      if (!a) throw new Error('域名解析不到 A 记录，请确认域名正确');
      return a.data;
    });
  }
  target.then(function(ip){
    return Promise.allSettled([
      api('/ip/lookup/' + encodeURIComponent(ip)),
      api('/ip/network/' + encodeURIComponent(ip)),
      api('/ip-type/' + encodeURIComponent(ip))
    ]).then(function(results){
      if (token !== viewToken) return;
      var box = document.getElementById('ipBox');
      if (!box) return;
      var lookup = results[0].status === 'fulfilled' ? results[0].value : null;
      var net = results[1].status === 'fulfilled' ? results[1].value : null;
      var type = results[2].status === 'fulfilled' ? results[2].value : null;
      if (!lookup && !net) {
        box.innerHTML = '<div class="err">查询失败：' + esc(results[0].reason ? results[0].reason.message : '请重试') + '</div>';
        return;
      }
      var badges = '';
      if (type && type.available) {
        if (type.hosting) badges += '<span class="badge b-yellow">机房</span>';
        if (type.mobile) badges += '<span class="badge b-blue">移动网络</span>';
        if (type.proxy) badges += '<span class="badge b-yellow">代理</span>';
      }
      if (net && net.ptr) badges += '<span class="badge b-blue">' + esc(net.ptr) + '</span>';
      var html = '<div class="card"><h3>目标</h3><div class="bigip" style="font-size:26px">' + esc(ip) + '</div><p>' + badges + '</p>' +
        (arg !== ip ? '<p class="muted">域名 ' + esc(arg) + ' 解析到该 IP。</p>' : '') + '</div>';
      if (lookup && lookup.sources && lookup.sources.length) {
        html += '<div class="card"><h3>归属地（多源合并）</h3><table><thead><tr><th>来源</th><th>国家</th><th>地区 / 城市</th><th>ISP / 组织</th><th>ASN</th><th>经纬度</th></tr></thead><tbody>';
        lookup.sources.forEach(function(g){
          html += '<tr><td>' + esc(g.source || '—') + '</td><td>' + esc(g.country || '—') + '</td><td>' + esc([g.region, g.city].filter(Boolean).join(' / ') || '—') + '</td><td>' + esc(g.isp || g.org || '—') + '</td><td>' + (g.asn ? 'AS' + esc(g.asn) : '—') + '</td><td>' + (g.latitude != null ? esc(g.latitude) + ', ' + esc(g.longitude) : '—') + '</td></tr>';
        });
        html += '</tbody></table></div>';
      }
      if (lookup && lookup.rdap) {
        var rdap = lookup.rdap;
        var events = {};
        (rdap.events || []).forEach(function(e){ events[e.eventAction] = e.eventDate; });
        html += '<div class="card"><h3>注册信息（RDAP）</h3><dl class="kv">' +
          '<dt>名称</dt><dd>' + esc(rdap.name || rdap.handle || '—') + '</dd>' +
          '<dt>注册时间</dt><dd>' + esc(events.registration || '—') + '</dd>' +
          '<dt>到期时间</dt><dd>' + esc(events.expiration || '—') + '</dd>' +
          '<dt>状态</dt><dd>' + esc((rdap.status || []).join(', ') || '—') + '</dd>' +
          '</dl><p><a href="#/whois/' + encodeURIComponent(ip) + '">查看完整 WHOIS →</a></p></div>';
      }
      if (net) {
        html += '<div class="card"><h3>网络拓扑</h3><dl class="kv">' +
          '<dt>前缀</dt><dd>' + esc(net.prefix || '—') + '</dd>' +
          '<dt>ASN</dt><dd>' + (net.asns || []).map(function(a){ return 'AS' + esc(a) + (net.holders && net.holders[a] ? '（' + esc(net.holders[a]) + '）' : ''); }).join('<br>') + '</dd>' +
          '<dt>反向解析</dt><dd>' + esc(net.ptr || '—') + '</dd>' +
          '<dt>路由</dt><dd>' + (net.routeAvailable ? '可查' : '暂不可查') + '</dd>' +
          '</dl>';
        if (net.topology && net.topology.nodes && net.topology.nodes.length) {
          html += '<h3 style="margin-top:14px">路由节点</h3><table><thead><tr><th>ASN</th><th>名称</th><th>占比</th></tr></thead><tbody>';
          net.topology.nodes.forEach(function(n){
            html += '<tr><td>AS' + esc(n.asn) + '</td><td>' + esc(n.name || '—') + '</td><td>' + (n.share != null ? esc(n.share) + '%' : '—') + '</td></tr>';
          });
          html += '</tbody></table>';
        }
        if (net.validations && net.validations.length) {
          html += '<h3 style="margin-top:14px">RPKI 校验</h3><table><thead><tr><th>前缀</th><th>ASN</th><th>状态</th></tr></thead><tbody>';
          net.validations.forEach(function(v){
            html += '<tr><td>' + esc(v.prefix || '—') + '</td><td>' + esc(v.asn || '—') + '</td><td>' + esc(v.status || '—') + '</td></tr>';
          });
          html += '</tbody></table>';
        }
        html += '</div>';
      }
      box.innerHTML = html;
    });
  }).catch(function(e){
    if (token !== viewToken) return;
    var box = document.getElementById('ipBox');
    if (box) box.innerHTML = '<div class="err">查询失败：' + esc(e.message || '请重试') + '</div>';
  });
}

/* ---------- 浏览器检测 ---------- */
function sha256Hex(str){
  if (!window.crypto || !crypto.subtle) return Promise.resolve('');
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)).then(function(buf){
    return Array.from(new Uint8Array(buf)).map(function(b){ return b.toString(16).padStart(2, '0'); }).join('');
  });
}
function gatherWebrtc(){
  return new Promise(function(resolve){
    var ips = {};
    try {
      var pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
      pc.createDataChannel('probe');
      pc.onicecandidate = function(e){
        if (e.candidate) {
          var m = e.candidate.candidate.match(/([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+|[0-9a-fA-F:]{2,})/);
          if (m) ips[m[1]] = true;
        }
      };
      pc.createOffer().then(function(o){ return pc.setLocalDescription(o); }).catch(function(){});
      setTimeout(function(){ try { pc.close(); } catch (e) {} resolve(Object.keys(ips)); }, 5000);
    } catch (e) { resolve([]); }
  });
}
function viewBrowser(app, token){
  app.innerHTML =
    '<h1>浏览器检测</h1>' +
    '<div class="grid">' +
    '<div class="card"><h3>基本信息</h3><dl class="kv">' +
    '<dt>User-Agent</dt><dd>' + esc(navigator.userAgent) + '</dd>' +
    '<dt>平台</dt><dd>' + esc(navigator.platform || '—') + '</dd>' +
    '<dt>语言</dt><dd>' + esc(navigator.language || '—') + '</dd>' +
    '<dt>时区</dt><dd>' + esc(Intl.DateTimeFormat().resolvedOptions().timeZone || '—') + '</dd>' +
    '<dt>屏幕</dt><dd>' + esc(screen.width + ' × ' + screen.height + '（' + (window.devicePixelRatio || 1) + 'x）') + '</dd>' +
    '<dt>CPU 核心</dt><dd>' + esc(navigator.hardwareConcurrency || '—') + '</dd>' +
    '<dt>设备内存</dt><dd>' + esc(navigator.deviceMemory ? navigator.deviceMemory + ' GB' : '—') + '</dd>' +
    '<dt>触屏</dt><dd>' + esc(('ontouchstart' in window) ? '支持' : '不支持') + '</dd>' +
    '<dt>联网</dt><dd>' + esc(navigator.onLine ? '在线' : '离线') + '</dd>' +
    '</dl></div>' +
    '<div class="card"><h3>指纹</h3><dl class="kv">' +
    '<dt>Canvas 指纹</dt><dd id="canvasFp">计算中…</dd>' +
    '<dt>访客 ID</dt><dd id="visitorId">计算中…</dd>' +
    '</dl><p class="muted">访客 ID 由 UA、屏幕、时区、语言组合哈希生成，仅在本地计算，不上传。</p></div>' +
    '</div>' +
    '<div class="card"><h3>TLS 指纹（边缘节点可见）</h3><div id="tlsBox"><div class="skel">正在获取…</div></div></div>' +
    '<div class="card"><h3>WebRTC 泄露检测</h3><div id="webrtcBox"><div class="skel">正在收集候选地址（约 5 秒）…</div></div>' +
    '<p class="muted">如果这里出现你的真实公网或内网 IP，说明浏览器通过 WebRTC 泄露了本地地址。现代浏览器默认会屏蔽本地地址，显示“未检出”是正常的好结果。</p></div>' +
    '<div class="card"><h3>验证演示（工作量证明）</h3><p class="muted">全球 Ping 用的就是这套轻量验证：浏览器本地算一道哈希题，替代图形验证码。</p>' +
    '<button class="btn" id="powBtn">完成一次验证</button> <span id="powOut" class="muted"></span></div>';
  try {
    var c = document.createElement('canvas');
    c.width = 200; c.height = 60;
    var ctx = c.getContext('2d');
    ctx.fillStyle = '#111827'; ctx.fillRect(0, 0, 200, 60);
    ctx.font = '16px Arial'; ctx.fillStyle = '#38bdf8';
    ctx.fillText('IP 工具箱指纹', 10, 30);
    ctx.fillStyle = '#e6edf3'; ctx.fillRect(10, 40, 80, 6);
    sha256Hex(c.toDataURL()).then(function(h){
      var el = document.getElementById('canvasFp');
      if (el && h) el.textContent = h.slice(0, 16);
    });
  } catch (e) {
    var el = document.getElementById('canvasFp');
    if (el) el.textContent = '无法计算';
  }
  sha256Hex(navigator.userAgent + '|' + screen.width + 'x' + screen.height + '|' + (Intl.DateTimeFormat().resolvedOptions().timeZone || '') + '|' + (navigator.language || '')).then(function(h){
    var el = document.getElementById('visitorId');
    if (el && h) el.textContent = h.slice(0, 16);
  });
  api('/browser/tls-fingerprint').then(function(d){
    if (token !== viewToken) return;
    var box = document.getElementById('tlsBox');
    if (!box) return;
    box.innerHTML = '<dl class="kv">' +
      '<dt>JA3</dt><dd>' + esc(d.ja3 || '未提供（当前套餐不返回该字段）') + '</dd>' +
      '<dt>JA4</dt><dd>' + esc(d.ja4 || '未提供（当前套餐不返回该字段）') + '</dd>' +
      '<dt>TLS 版本</dt><dd>' + esc(d.tlsVersion || '—') + '</dd>' +
      '<dt>加密套件</dt><dd>' + esc(d.tlsCipher || '—') + '</dd>' +
      '<dt>机器人评分</dt><dd>' + esc(d.botManagement && d.botManagement.score != null ? String(d.botManagement.score) : '—') + '</dd>' +
      '</dl>';
  }).catch(function(e){
    if (token !== viewToken) return;
    var box = document.getElementById('tlsBox');
    if (box) box.innerHTML = '<div class="err">获取失败：' + esc(e.message || '请重试') + '</div>';
  });
  gatherWebrtc().then(function(ips){
    if (token !== viewToken) return;
    var box = document.getElementById('webrtcBox');
    if (!box) return;
    box.innerHTML = ips.length
      ? '<p>检出以下候选地址：</p><p>' + ips.map(function(ip){ return '<span class="badge b-yellow">' + esc(ip) + '</span>'; }).join('') + '</p>'
      : '<p><span class="badge b-green">未检出</span> <span class="muted">未发现 WebRTC 候选地址，浏览器已屏蔽本地地址泄露。</span></p>';
  });
  document.getElementById('powBtn').addEventListener('click', function(){
    var out = document.getElementById('powOut');
    out.textContent = '计算中…';
    api('/browser/challenges').then(function(ch){
      var c = ch.challenge;
      return solvePow(c).then(function(s){
        return api('/browser/challenges/verify', { method: 'POST', body: { provider: 'pow', challenge: c.nonce, answer: s.answer } });
      });
    }).then(function(res){
      out.textContent = res.success ? '验证通过。' : ('验证未通过：' + (res.message || '请重试'));
    }).catch(function(e){
      out.textContent = '验证失败：' + (e.message || '请重试');
    });
  });
}


/* ---------- 主题（浅色 / 深色） ---------- */
var MOON_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
var SUN_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="M4.9 4.9l1.4 1.4"/><path d="M17.7 17.7l1.4 1.4"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="M4.9 19.1l1.4-1.4"/><path d="M17.7 6.3l1.4-1.4"/></svg>';
function applyTheme(dark){
  document.documentElement.classList.toggle('dark', !!dark);
  var icon = document.getElementById('themeIcon');
  if (icon) icon.innerHTML = dark ? SUN_SVG : MOON_SVG;
  try { localStorage.setItem('one-ip-theme', dark ? 'dark' : 'light'); } catch (e) {}
}
(function initTheme(){
  var saved = null;
  try { saved = localStorage.getItem('one-ip-theme'); } catch (e) {}
  applyTheme(saved === 'dark');
  var btn = document.getElementById('themeToggle');
  if (btn) btn.addEventListener('click', function(){
    applyTheme(!document.documentElement.classList.contains('dark'));
  });
})();

render();
</script>
</body>
</html>`;
