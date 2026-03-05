/**
 * Core Scanner - orchestrates rule-based and LLM-assisted detection layers.
 *
 * The Scanner is the primary entry point for prompt injection detection.
 */

import * as crypto from "crypto";
import { LLMDetector, LLMDetectionResult } from "./llmDetector";
import { Rule, RuleEngine, RuleMatch, RuleSeverity, severityScore } from "./rules";
import { Sanitizer, SanitizationMode } from "./sanitizer";

export enum ThreatLevel {
  SAFE = "safe",
  SUSPICIOUS = "suspicious",
  THREAT = "threat",
  CRITICAL = "critical",
}

export function isThreat(level: ThreatLevel): boolean {
  return level === ThreatLevel.THREAT || level === ThreatLevel.CRITICAL;
}

export interface ScanResult {
  /** The original (unmodified) content that was scanned */
  content: string;
  /** Content after sanitization (undefined if SAFE and sanitizeSafeContent=false) */
  sanitizedContent?: string;
  threatLevel: ThreatLevel;
  confidence: number;
  isThreat: boolean;
  ruleMatches: RuleMatch[];
  llmResult?: LLMDetectionResult;
  /** SHA-256 hash (first 16 chars) of the original content */
  contentHash: string;
  /** Time taken to scan in milliseconds */
  scanDurationMs: number;
  metadata: Record<string, unknown>;
}

export interface ScannerOptions {
  llmDetector?: LLMDetector;
  sanitizationMode?: SanitizationMode;
  customRules?: Rule[];
  rulesThreatThreshold?: number;
  llmThreatThreshold?: number;
  useLlmForSuspicious?: boolean;
  sanitizeSafeContent?: boolean;
}

export class Scanner {
  private ruleEngine: RuleEngine;
  private llmDetector?: LLMDetector;
  private sanitizer: Sanitizer;
  private rulesThreatThreshold: number;
  private llmThreatThreshold: number;
  private useLlmForSuspicious: boolean;
  private sanitizeSafeContent: boolean;

  constructor(options: ScannerOptions = {}) {
    this.ruleEngine = new RuleEngine(options.customRules);
    this.llmDetector = options.llmDetector;
    this.sanitizer = new Sanitizer(
      options.sanitizationMode ?? SanitizationMode.LABEL
    );
    this.rulesThreatThreshold = options.rulesThreatThreshold ?? 0.5;
    this.llmThreatThreshold = options.llmThreatThreshold ?? 0.75;
    this.useLlmForSuspicious = options.useLlmForSuspicious ?? true;
    this.sanitizeSafeContent = options.sanitizeSafeContent ?? false;
  }

  async scan(
    content: string,
    metadata: Record<string, unknown> = {},
    forceLlm = false
  ): Promise<ScanResult> {
    const t0 = performance.now();
    const contentHash = crypto
      .createHash("sha256")
      .update(content)
      .digest("hex")
      .slice(0, 16);

    // Layer 1: Rule-based detection
    const ruleMatches = this.ruleEngine.scan(content);
    const rulesConfidence = this.aggregateRuleConfidence(ruleMatches);
    const ruleThreat = rulesConfidence >= this.rulesThreatThreshold;

    // Layer 2: LLM detection (conditional)
    let llmResult: LLMDetectionResult | undefined;

    const shouldRunLlm =
      this.llmDetector?.isConfigured &&
      (forceLlm ||
        ruleThreat ||
        (this.useLlmForSuspicious && rulesConfidence > 0));

    if (shouldRunLlm && this.llmDetector) {
      try {
        llmResult = await this.llmDetector.detect(content);
      } catch (err) {
        // fall through - rules-only result
      }
    }

    // Combine signals
    const { threatLevel, confidence } = this.classify(
      ruleMatches,
      rulesConfidence,
      llmResult
    );
    const threat = isThreat(threatLevel);

    // Sanitize
    let sanitizedContent: string | undefined;
    if (threat || this.sanitizeSafeContent) {
      const spans = ruleMatches.map(
        (m): [number, number] => [m.start, m.end]
      );
      sanitizedContent = this.sanitizer.sanitize(
        content,
        spans.length > 0 ? spans : undefined
      );
    }

    const scanDurationMs = performance.now() - t0;

    return {
      content,
      sanitizedContent,
      threatLevel,
      confidence,
      isThreat: threat,
      ruleMatches,
      llmResult,
      contentHash,
      scanDurationMs: Math.round(scanDurationMs * 100) / 100,
      metadata,
    };
  }

  async scanBatch(
    contents: string[],
    metadata?: Array<Record<string, unknown> | undefined>
  ): Promise<ScanResult[]> {
    return Promise.all(
      contents.map((c, i) => this.scan(c, metadata?.[i] ?? {}))
    );
  }

  addRule(rule: Rule): void {
    this.ruleEngine.addRule(rule);
  }

  removeRule(ruleId: string): boolean {
    return this.ruleEngine.removeRule(ruleId);
  }

  disableRule(ruleId: string): boolean {
    return this.ruleEngine.disableRule(ruleId);
  }

  private aggregateRuleConfidence(matches: RuleMatch[]): number {
    if (matches.length === 0) return 0;

    const maxScore = Math.max(...matches.map((m) => severityScore(m.severity)));
    const uniqueRules = new Set(matches.map((m) => m.ruleId)).size;
    const boost = Math.min((uniqueRules - 1) * 0.1, 0.25);

    return Math.min(maxScore + boost, 1.0);
  }

  private classify(
    ruleMatches: RuleMatch[],
    rulesConfidence: number,
    llmResult?: LLMDetectionResult
  ): { threatLevel: ThreatLevel; confidence: number } {
    const llmConfidence =
      llmResult && !llmResult.usedFallback ? llmResult.confidence : 0;
    const llmFlagged =
      !!llmResult && llmResult.isInjection && !llmResult.usedFallback;

    let confidence: number;
    if (rulesConfidence > 0 && llmConfidence > 0) {
      confidence =
        0.6 * Math.max(rulesConfidence, llmConfidence) +
        0.4 * ((rulesConfidence + llmConfidence) / 2);
    } else {
      confidence = Math.max(rulesConfidence, llmConfidence);
    }

    if (confidence === 0) {
      return { threatLevel: ThreatLevel.SAFE, confidence: 0 };
    }

    const hasCritical = ruleMatches.some(
      (m) => m.severity === RuleSeverity.CRITICAL
    );

    if (hasCritical || confidence >= 0.9) {
      return { threatLevel: ThreatLevel.CRITICAL, confidence };
    } else if (confidence >= this.llmThreatThreshold || llmFlagged) {
      return { threatLevel: ThreatLevel.THREAT, confidence };
    } else if (confidence >= this.rulesThreatThreshold) {
      return { threatLevel: ThreatLevel.THREAT, confidence };
    } else {
      return { threatLevel: ThreatLevel.SUSPICIOUS, confidence };
    }
  }
}
