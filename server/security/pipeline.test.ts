import { describe, expect, it } from "vitest";
import { normalizeEvent } from "./pipeline";

describe("normalizeEvent", () => {
  it("normalizes syslog authentication failures", () => {
    const event = normalizeEvent(
      "syslog",
      "Apr 10 12:00:01 web-01 sshd[101]: Failed password for invalid user admin from 91.240.118.12 port 49222 ssh2",
    );

    expect(event.eventType).toBe("authentication_failed");
    expect(event.eventCategory).toBe("identity");
    expect(event.sourceIp).toBe("91.240.118.12");
    expect(event.hostname).toBe("web-01");
  });

  it("normalizes JSON endpoint telemetry", () => {
    const event = normalizeEvent("json", {
      eventType: "suspicious_process",
      eventCategory: "endpoint",
      sourceIp: "10.0.0.5",
      destinationIp: "8.8.8.8",
      hostname: "ws-001",
      username: "alex",
      processName: "powershell.exe",
      message: "Suspicious encoded PowerShell observed",
      severity: "high",
    });

    expect(event.eventType).toBe("suspicious_process");
    expect(event.eventCategory).toBe("endpoint");
    expect(event.destinationIp).toBe("8.8.8.8");
    expect(event.hostname).toBe("ws-001");
    expect(event.severity).toBe("high");
  });
});
