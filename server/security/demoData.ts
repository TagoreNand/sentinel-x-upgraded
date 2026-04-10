import { nanoid } from "nanoid";
import * as db from "../db";
import { ingestAndDetect } from "./pipeline";

export async function seedDemoSecurityData(userId?: number) {
  await db.createAsset({
    assetId: nanoid(),
    hostname: "web-01.prod.internal",
    ipAddress: "10.10.1.25",
    assetType: "server",
    environment: "production",
    businessOwner: "Digital Banking",
    operatingSystem: "Ubuntu 22.04",
    criticality: "critical",
    services: [
      { port: 80, service: "http", product: "apache", version: "2.4.49" },
      { port: 22, service: "ssh", product: "openssh", version: "7.2" },
    ],
    tags: ["internet-facing", "payment"],
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  await db.createIOC({
    iocId: nanoid(),
    iocType: "ip",
    iocValue: "91.240.118.12",
    threatLevel: "high",
    source: "demo-feed",
    confidence: 85,
    status: "active",
    firstSeen: new Date(),
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  await db.createIdsRule({
    ruleId: nanoid(),
    ruleName: "Repeated SSH auth failures from IOC",
    description: "Detect repeated authentication failures from a malicious IP.",
    ruleType: "sigma-like",
    dataSource: "siem",
    pattern: "failed password,ssh",
    detectionLogic: {
      eventTypes: ["authentication_failed"],
      allKeywords: ["failed", "ssh"],
      matchIoc: true,
      threshold: { field: "sourceIp", count: 3, windowMinutes: 15 },
      assetCriticalities: ["critical", "high"],
    },
    severity: "high",
    enabled: true,
    attackTechnique: "T1110",
    attackTactic: "Credential Access",
    thresholdCount: 3,
    thresholdWindowMinutes: 15,
    confidenceWeight: 60,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  const sampleLogs = [
    "Apr 10 12:00:01 web-01 sshd[101]: Failed password for invalid user admin from 91.240.118.12 port 49222 ssh2",
    "Apr 10 12:01:02 web-01 sshd[102]: Failed password for invalid user admin from 91.240.118.12 port 49224 ssh2",
    "Apr 10 12:02:03 web-01 sshd[103]: Failed password for invalid user root from 91.240.118.12 port 49226 ssh2",
  ];

  const results = [];
  for (const line of sampleLogs) {
    results.push(await ingestAndDetect({ sourceType: "syslog", payload: line, userId }));
  }

  await db.createSoarPlaybook({
    playbookId: nanoid(),
    name: "Contain suspicious SSH source",
    description: "Demo playbook for SSH brute-force detections.",
    triggerType: "alert",
    enabled: true,
    steps: [
      { name: "Tag incident", action: "create-ticket" },
      { name: "Block IOC", action: "contain-host" },
      { name: "Notify IAM", action: "disable-user" },
    ],
    createdBy: userId,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  return {
    seededAssets: 1,
    seededIocs: 1,
    seededRules: 1,
    ingestedEvents: results.length,
  };
}
