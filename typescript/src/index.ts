/**
 * sentinel-inject - Prompt Injection Scanner for AI Agents
 *
 * @example
 * import { Scanner, ThreatLevel } from "sentinel-inject";
 *
 * const scanner = new Scanner();
 * const result = await scanner.scan("Ignore all previous instructions...");
 * if (result.isThreat) {
 *   console.log(`Blocked! Confidence: ${Math.round(result.confidence * 100)}%`);
 * }
 */

export { Scanner, ScanResult, ThreatLevel, isThreat, ScannerOptions } from "./scanner";
export { RuleEngine, Rule, RuleMatch, RuleSeverity, severityScore } from "./rules";
export { Sanitizer, SanitizationMode } from "./sanitizer";
export { Middleware, MiddlewareConfig, InjectionDetectedError } from "./middleware";
export {
  LLMDetector,
  LLMDetectorConfig,
  LLMDetectionResult,
  ClassifierFn,
} from "./llmDetector";
export { ScanLogger, ScanMetrics, AuditTrail, ScanEvent, ScanEventName } from "./observability";
