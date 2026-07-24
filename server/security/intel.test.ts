import { describe, expect, it } from "vitest";
import {
  extractMispAttributes,
  extractStixObjects,
  mapMispType,
  mapStixObjectType,
  parseMispAttributes,
  parseStixObjects,
  parseStixPattern,
} from "./intel";

describe("mapStixObjectType", () => {
  it("maps common STIX SCO types to IOC types", () => {
    expect(mapStixObjectType("ipv4-addr", "value")).toBe("ip");
    expect(mapStixObjectType("ipv6-addr", "value")).toBe("ip");
    expect(mapStixObjectType("domain-name", "value")).toBe("domain");
    expect(mapStixObjectType("url", "value")).toBe("url");
    expect(mapStixObjectType("email-addr", "value")).toBe("email");
    expect(mapStixObjectType("windows-registry-key", "key")).toBe("registry");
    expect(mapStixObjectType("file", "hashes.'SHA-256'")).toBe("hash");
    expect(mapStixObjectType("file", "name")).toBe("file");
  });

  it("returns null for unmapped types and file sub-properties we can't use", () => {
    expect(mapStixObjectType("autonomous-system", "number")).toBeNull();
    expect(mapStixObjectType("file", "size")).toBeNull();
  });
});

describe("parseStixPattern", () => {
  it("extracts a single observable", () => {
    expect(parseStixPattern("[ipv4-addr:value = '1.2.3.4']")).toEqual([{ iocType: "ip", iocValue: "1.2.3.4", confidence: undefined }]);
  });

  it("extracts a file hash", () => {
    const r = parseStixPattern("[file:hashes.'SHA-256' = 'aabbccddeeff']");
    expect(r).toEqual([{ iocType: "hash", iocValue: "aabbccddeeff", confidence: undefined }]);
  });

  it("extracts every observable from an OR-joined pattern", () => {
    const r = parseStixPattern("[ipv4-addr:value = '1.1.1.1' OR ipv4-addr:value = '2.2.2.2']");
    expect(r.map((i) => i.iocValue)).toEqual(["1.1.1.1", "2.2.2.2"]);
  });

  it("carries confidence through", () => {
    expect(parseStixPattern("[domain-name:value = 'evil.com']", 90)[0].confidence).toBe(90);
  });

  it("yields nothing for an unparsable pattern", () => {
    expect(parseStixPattern("[network-traffic:src_ref.type = 'ipv4-addr']")).toEqual([]);
    expect(parseStixPattern("garbage")).toEqual([]);
  });

  it("fails closed on LIKE (wildcard) comparisons rather than storing the literal", () => {
    // '10.0.0.%' is a wildcard, not an observable — must not become an IOC.
    expect(parseStixPattern("[ipv4-addr:value LIKE '10.0.0.%']")).toEqual([]);
    expect(parseStixPattern("[domain-name:value LIKE '%.evil.com']")).toEqual([]);
    // A mixed pattern still extracts the exact-equality observable.
    const mixed = parseStixPattern("[url:value = 'http://bad.test/a' OR url:value LIKE '%/b']");
    expect(mixed.map((i) => i.iocValue)).toEqual(["http://bad.test/a"]);
  });

  it("decodes STIX string escapes and does not truncate on an escaped quote", () => {
    // Backslash-escaped path: \\ -> \
    const reg = parseStixPattern("[windows-registry-key:key = 'HKLM\\\\Software\\\\Run']");
    expect(reg[0].iocValue).toBe("HKLM\\Software\\Run");
    // Escaped single quote: the value must not stop at the escaped quote.
    const name = parseStixPattern("[file:name = 'O\\'Brien.exe']");
    expect(name[0].iocValue).toBe("O'Brien.exe");
  });
});

describe("parseStixObjects", () => {
  it("parses indicators and skips non-indicators without counting them as errors", () => {
    const result = parseStixObjects([
      { type: "indicator", pattern: "[ipv4-addr:value = '9.9.9.9']" },
      { type: "identity", name: "ACME" },
      { type: "indicator", pattern: "[url:value = 'http://bad.example/x']" },
    ]);
    expect(result.iocs.map((i) => i.iocValue)).toEqual(["9.9.9.9", "http://bad.example/x"]);
    expect(result.skipped).toBe(0);
  });

  it("counts indicators with unparsable patterns as skipped", () => {
    const result = parseStixObjects([{ type: "indicator", pattern: "[network-traffic:protocols[0] = 'tcp']" }]);
    expect(result.iocs).toHaveLength(0);
    expect(result.skipped).toBe(1);
  });
});

describe("extractStixObjects", () => {
  it("handles bundles, envelopes, arrays, and garbage", () => {
    expect(extractStixObjects({ type: "bundle", objects: [{ a: 1 }] })).toEqual([{ a: 1 }]);
    expect(extractStixObjects({ objects: [{ b: 2 }] })).toEqual([{ b: 2 }]);
    expect(extractStixObjects([{ c: 3 }])).toEqual([{ c: 3 }]);
    expect(extractStixObjects("nope")).toEqual([]);
    expect(extractStixObjects(null)).toEqual([]);
  });
});

describe("mapMispType", () => {
  it("maps common MISP attribute types", () => {
    expect(mapMispType("ip-dst")).toBe("ip");
    expect(mapMispType("ip-src")).toBe("ip");
    expect(mapMispType("domain")).toBe("domain");
    expect(mapMispType("hostname")).toBe("domain");
    expect(mapMispType("url")).toBe("url");
    expect(mapMispType("sha256")).toBe("hash");
    expect(mapMispType("email-src")).toBe("email");
    expect(mapMispType("filename")).toBe("file");
  });

  it("fails closed on composite and unknown types", () => {
    expect(mapMispType("filename|sha256")).toBeNull();
    expect(mapMispType("btc")).toBeNull();
  });
});

describe("extractMispAttributes", () => {
  it("handles the restSearch envelope and bare forms", () => {
    expect(extractMispAttributes({ response: { Attribute: [{ x: 1 }] } })).toEqual([{ x: 1 }]);
    expect(extractMispAttributes({ Attribute: [{ y: 2 }] })).toEqual([{ y: 2 }]);
    expect(extractMispAttributes([{ z: 3 }])).toEqual([{ z: 3 }]);
    expect(extractMispAttributes({})).toEqual([]);
  });
});

describe("parseMispAttributes", () => {
  it("maps supported attributes and skips the rest", () => {
    const result = parseMispAttributes([
      { type: "ip-dst", value: "5.5.5.5" },
      { type: "domain", value: "evil.example" },
      { type: "btc", value: "1abc" }, // unsupported -> skipped
      { type: "sha256", value: "deadbeef", to_ids: true },
    ]);
    expect(result.iocs.map((i) => `${i.iocType}:${i.iocValue}`)).toEqual(["ip:5.5.5.5", "domain:evil.example", "hash:deadbeef"]);
    expect(result.skipped).toBe(1);
  });

  it("honors MISP to_ids=false by skipping the attribute", () => {
    const result = parseMispAttributes([{ type: "ip-dst", value: "7.7.7.7", to_ids: false }]);
    expect(result.iocs).toHaveLength(0);
    expect(result.skipped).toBe(1);
  });

  it("skips empty or malformed values", () => {
    const result = parseMispAttributes([{ type: "ip-dst", value: "" }, { type: "ip-dst" }, "nope"]);
    expect(result.iocs).toHaveLength(0);
    expect(result.skipped).toBe(3);
  });
});
