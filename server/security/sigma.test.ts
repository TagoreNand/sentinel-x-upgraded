import { describe, expect, it } from "vitest";
import { translateSigmaRules, type SigmaTranslation } from "./sigma";

function only(result: SigmaTranslation[]): SigmaTranslation {
  expect(result).toHaveLength(1);
  return result[0];
}

function imported(result: SigmaTranslation[]) {
  const t = only(result);
  if (!t.imported) throw new Error(`expected import, got skip: ${t.reason}`);
  return t;
}

describe("translateSigmaRules — supported mappings", () => {
  it("maps a structured single-selection rule with level and ATT&CK tags", () => {
    const t = imported(
      translateSigmaRules(`
title: SSH authentication failures
description: Detects failed SSH logins
logsource:
  category: authentication
detection:
  selection:
    eventType: authentication_failed
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1110
`),
    );
    expect(t.rule.ruleName).toBe("SSH authentication failures");
    expect(t.rule.severity).toBe("high");
    expect(t.rule.detectionLogic.eventTypes).toEqual(["authentication_failed"]);
    expect(t.rule.attackTechnique).toBe("T1110");
    expect(t.rule.attackTactic).toBe("Credential Access");
    expect(t.rule.dataSource).toBe("sigma");
    expect(t.rule.description).toContain("logsource.category=authentication");
  });

  it("maps a scalar keyword list to anyKeywords (OR)", () => {
    const t = imported(
      translateSigmaRules(`
title: Credential dumping tools
detection:
  keywords:
    - mimikatz
    - sekurlsa
  condition: keywords
`),
    );
    expect(t.rule.detectionLogic.anyKeywords).toEqual(["mimikatz", "sekurlsa"]);
    expect(t.rule.severity).toBe("medium"); // default when no level
  });

  it("translates count() aggregations into thresholds", () => {
    const gt = imported(
      translateSigmaRules(`
title: Brute force
detection:
  selection:
    eventType: authentication_failed
  condition: selection | count() by sourceIp > 5
level: high
`),
    );
    // `> 5` fires on the 6th event.
    expect(gt.rule.detectionLogic.threshold).toEqual({ count: 6, windowMinutes: 5, field: "sourceIp" });
    expect(gt.rule.thresholdCount).toBe(6);

    const gte = imported(
      translateSigmaRules(`
title: Brute force gte
detection:
  selection:
    eventType: authentication_failed
  condition: selection | count() by User >= 5
`),
    );
    expect(gte.rule.detectionLogic.threshold).toEqual({ count: 5, windowMinutes: 5, field: "username" });
  });

  it("maps |contains and scalar fields to allKeywords (AND)", () => {
    const t = imported(
      translateSigmaRules(`
title: Suspicious command
detection:
  selection:
    CommandLine|contains: whoami
    Image: powershell.exe
  condition: selection
`),
    );
    expect(t.rule.detectionLogic.allKeywords).toEqual(["whoami", "powershell.exe"]);
  });

  it("maps |re to a regex condition and warns about scope/case divergence", () => {
    const t = imported(
      translateSigmaRules(`
title: Encoded powershell
detection:
  selection:
    CommandLine|re: 'powershell.*-enc'
  condition: selection
`),
    );
    expect(t.rule.detectionLogic.rawRegex).toBe("powershell.*-enc");
    expect(t.warnings.join(" ")).toMatch(/case-insensitively to the whole log/i);
  });

  it("warns that count() thresholds are entity-scoped, not selection-scoped", () => {
    const t = imported(
      translateSigmaRules(`
title: Brute force
detection:
  selection:
    eventType: authentication_failed
  condition: selection | count() by sourceIp > 5
`),
    );
    expect(t.warnings.join(" ")).toMatch(/counts all events from the sourceIp/i);
  });

  it("maps every Sigma level onto a severity", () => {
    const levels: Record<string, string> = {
      informational: "low",
      low: "low",
      medium: "medium",
      high: "high",
      critical: "critical",
    };
    for (const [level, severity] of Object.entries(levels)) {
      const t = imported(
        translateSigmaRules(`
title: level ${level}
detection:
  selection:
    eventType: x
  condition: selection
level: ${level}
`),
      );
      expect(t.rule.severity).toBe(severity);
    }
  });

  it("warns (but imports) when startswith is approximated", () => {
    const t = imported(
      translateSigmaRules(`
title: Windows path
detection:
  selection:
    Image|startswith: 'C:\\\\Windows'
  condition: selection
`),
    );
    expect(t.warnings.join(" ")).toMatch(/approximated as substring/);
  });

  it("handles a multi-document Sigma stream", () => {
    const result = translateSigmaRules(`
title: Rule A
detection:
  selection:
    eventType: a
  condition: selection
---
title: Rule B
detection:
  selection:
    eventType: b
  condition: selection
`);
    expect(result).toHaveLength(2);
    expect(result.every((r) => r.imported)).toBe(true);
  });
});

describe("translateSigmaRules — fail-closed rejections", () => {
  const cases: { name: string; yaml: string; reason: RegExp }[] = [
    {
      name: "boolean conditions",
      yaml: `title: t\ndetection:\n  selection:\n    eventType: a\n  filter:\n    eventType: b\n  condition: selection and not filter`,
      reason: /boolean conditions/i,
    },
    {
      name: "1 of / all of",
      yaml: `title: t\ndetection:\n  selection1:\n    eventType: a\n  condition: 1 of selection*`,
      reason: /1 of.*all of/i,
    },
    {
      name: "list-of-maps selection",
      yaml: `title: t\ndetection:\n  selection:\n    - eventType: a\n    - eventType: b\n  condition: selection`,
      reason: /list-of-maps/i,
    },
    {
      name: "unsupported modifier",
      yaml: `title: t\ndetection:\n  selection:\n    SourceIp|cidr: 10.0.0.0/8\n  condition: selection`,
      reason: /modifier '\|cidr'/i,
    },
    {
      name: "multiple OR keyword groups",
      yaml: `title: t\ndetection:\n  selection:\n    FieldA:\n      - a1\n      - a2\n    FieldB:\n      - b1\n      - b2\n  condition: selection`,
      reason: /multiple OR keyword groups/i,
    },
    {
      name: "unknown selection reference",
      yaml: `title: t\ndetection:\n  selection:\n    eventType: a\n  condition: nope`,
      reason: /unknown selection/i,
    },
    {
      name: "missing detection block",
      yaml: `title: t\nlevel: high`,
      reason: /missing detection/i,
    },
    {
      name: "unsupported aggregation",
      yaml: `title: t\ndetection:\n  selection:\n    eventType: a\n  condition: selection | sum(Bytes) > 100`,
      reason: /unsupported aggregation/i,
    },
  ];

  for (const c of cases) {
    it(`rejects ${c.name} with a reason`, () => {
      const t = only(translateSigmaRules(c.yaml));
      expect(t.imported).toBe(false);
      if (!t.imported) expect(t.reason).toMatch(c.reason);
    });
  }

  it("rejects rules that exceed the pipeline's keyword bounds", () => {
    const keywords = Array.from({ length: 30 }, (_, i) => `kw${i}`);
    const yaml = `title: too many\ndetection:\n  keywords:\n${keywords.map((k) => `    - ${k}`).join("\n")}\n  condition: keywords`;
    const t = only(translateSigmaRules(yaml));
    expect(t.imported).toBe(false);
    if (!t.imported) expect(t.reason).toMatch(/exceeds rule limits/i);
  });

  it("does not throw on malformed YAML — returns a skip", () => {
    const t = only(translateSigmaRules("title: [unclosed sequence"));
    expect(t.imported).toBe(false);
  });

  it("rejects `Field: null` absence tests instead of matching literal 'null'", () => {
    const t = only(
      translateSigmaRules(`
title: Parentless process
detection:
  selection:
    ParentImage: null
  condition: selection
`),
    );
    expect(t.imported).toBe(false);
    if (!t.imported) expect(t.reason).toMatch(/null match/i);
  });

  it("rejects null entries inside a keyword list", () => {
    const t = only(
      translateSigmaRules(`
title: keywords with null
detection:
  keywords:
    - foo
    - null
  condition: keywords
`),
    );
    expect(t.imported).toBe(false);
  });

  it("rejects two distinct fields mapping to one structured slot (Sigma AND, unrepresentable)", () => {
    const t = only(
      translateSigmaRules(`
title: subject acts on target
detection:
  selection:
    TargetUserName: admin
    SubjectUserName: victim
  condition: selection
`),
    );
    expect(t.imported).toBe(false);
    if (!t.imported) expect(t.reason).toMatch(/not representable/i);
  });

  it("does not throw on a YAML alias bomb — returns a skip", () => {
    const bomb = `
a: &a [x,x,x,x,x,x,x,x,x,x]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c,*c]
detection:
  selection:
    eventType: x
  condition: selection
`;
    let result: SigmaTranslation[] = [];
    expect(() => {
      result = translateSigmaRules(bomb);
    }).not.toThrow();
    expect(result[0]?.imported).toBe(false);
  });

  it("skips empty documents between separators without erroring", () => {
    const result = translateSigmaRules(`
title: Only rule
detection:
  selection:
    eventType: a
  condition: selection
---
`);
    expect(result).toHaveLength(1);
    expect(result[0].imported).toBe(true);
  });
});
