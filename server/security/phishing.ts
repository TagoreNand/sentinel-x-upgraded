import { nanoid } from "nanoid";
import * as db from "../db";

function extractUrls(text: string): string[] {
  return text.match(/https?:\/\/[^\s)]+/gi) ?? [];
}

function suspiciousSender(sender: string) {
  const lower = sender.toLowerCase();
  return /(support-|secure-|verify-|alerts?@|billing@)/.test(lower) || /(\.ru|\.xyz|\.top|\.click)/.test(lower);
}

export async function analyzePhishingEmail(input: {
  subject: string;
  sender: string;
  recipient?: string;
  body: string;
  attachmentCount?: number;
  createIncident?: boolean;
  userId?: number;
}) {
  const urls = extractUrls(input.body);
  const reasons: string[] = [];
  const indicators: string[] = [];
  let score = 35;

  if (suspiciousSender(input.sender)) {
    score += 20;
    reasons.push("Sender profile matches known phishing naming patterns");
    indicators.push(`sender:${input.sender}`);
  }
  if (/(urgent|immediately|verify your account|password expires|invoice attached|wire transfer)/i.test(`${input.subject} ${input.body}`)) {
    score += 15;
    reasons.push("Urgency or coercion language detected");
  }
  if (urls.length > 0) {
    score += 10;
    reasons.push(`Email contains ${urls.length} URL(s)`);
    indicators.push(...urls.map((url) => `url:${url}`));
  }
  if ((input.attachmentCount ?? 0) > 0) {
    score += 10;
    reasons.push(`Email has ${input.attachmentCount} attachment(s)`);
  }
  if (/(enable content|macro|docm|html attachment)/i.test(input.body)) {
    score += 20;
    reasons.push("Attachment lure or macro execution wording present");
  }

  const verdict = score >= 75 ? "malicious" : score >= 55 ? "suspicious" : "benign";

  let linkedIncidentId: number | undefined;
  if (input.createIncident && verdict !== "benign") {
    const incident = await db.createIncident({
      incidentId: nanoid(),
      title: `Phishing email triage: ${input.subject}`,
      description: `Auto-created from phishing analysis for sender ${input.sender}`,
      severity: verdict === "malicious" ? "high" : "medium",
      status: "open",
      classification: "phishing",
      createdBy: input.userId,
      detectedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    linkedIncidentId = Number((incident as any)?.insertId || 0) || undefined;
  }

  const insert = await db.createPhishingAnalysis({
    analysisId: nanoid(),
    emailSubject: input.subject,
    sender: input.sender,
    recipient: input.recipient,
    urlCount: urls.length,
    attachmentCount: input.attachmentCount ?? 0,
    verdict: verdict as any,
    confidence: Math.min(score, 95),
    reasons,
    indicators,
    linkedIncidentId,
    createdAt: new Date(),
  });

  return {
    analysisId: Number((insert as any)?.insertId || 0),
    verdict,
    confidence: Math.min(score, 95),
    reasons,
    indicators,
    linkedIncidentId,
  };
}
