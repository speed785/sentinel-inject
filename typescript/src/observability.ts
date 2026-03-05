export interface ScanMetrics {
  totalScans: number;
  injectionsDetected: number;
  injectionsBlocked: number;
  llmCalls: number;
  avgConfidence: number;
  avgLatencyMs: number;
  falsePositives: number;
  llmCostUsd: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
}

export type ScanEventName =
  | "scan_started"
  | "rule_matched"
  | "llm_classified"
  | "scan_complete"
  | "injection_blocked";

export interface ScanEvent {
  event: ScanEventName;
  timestamp: string;
  content_hash: string;
  rule_ids_fired: string[];
  confidence: number;
  action_taken: string;
  latency_ms: number;
  [key: string]: unknown;
}

export class ScanLogger {
  private latencies: number[] = [];

  metrics: ScanMetrics = {
    totalScans: 0,
    injectionsDetected: 0,
    injectionsBlocked: 0,
    llmCalls: 0,
    avgConfidence: 0,
    avgLatencyMs: 0,
    falsePositives: 0,
    llmCostUsd: 0,
    p50LatencyMs: 0,
    p95LatencyMs: 0,
    p99LatencyMs: 0,
  };

  emit(event: Omit<ScanEvent, "timestamp">): void {
    const payload = {
      ...(event as Record<string, unknown>),
      timestamp: new Date().toISOString(),
    };
    console.log(JSON.stringify(payload));
  }

  recordScan(
    confidence: number,
    latencyMs: number,
    isThreat: boolean,
    isBlocked: boolean
  ): void {
    this.metrics.totalScans += 1;
    if (isThreat) this.metrics.injectionsDetected += 1;
    if (isBlocked) this.metrics.injectionsBlocked += 1;

    const n = this.metrics.totalScans;
    this.metrics.avgConfidence =
      (this.metrics.avgConfidence * (n - 1) + confidence) / n;
    this.metrics.avgLatencyMs =
      (this.metrics.avgLatencyMs * (n - 1) + latencyMs) / n;
    this.latencies.push(latencyMs);
    this.metrics.p50LatencyMs = this.percentile(50);
    this.metrics.p95LatencyMs = this.percentile(95);
    this.metrics.p99LatencyMs = this.percentile(99);
  }

  markFalsePositive(): void {
    this.metrics.falsePositives += 1;
  }

  recordLlmCall(tokensUsed: number, costUsd?: number): void {
    this.metrics.llmCalls += 1;
    const estimated = costUsd ?? (tokensUsed / 1000) * 0.00015;
    this.metrics.llmCostUsd += estimated;
  }

  exportPrometheus(): string {
    const m = this.metrics;
    return [
      "# HELP sentinel_scans_total Total number of scans",
      "# TYPE sentinel_scans_total counter",
      `sentinel_scans_total ${m.totalScans}`,
      "# HELP sentinel_injections_detected_total Injections detected",
      "# TYPE sentinel_injections_detected_total counter",
      `sentinel_injections_detected_total ${m.injectionsDetected}`,
      "# HELP sentinel_injections_blocked_total Injections blocked",
      "# TYPE sentinel_injections_blocked_total counter",
      `sentinel_injections_blocked_total ${m.injectionsBlocked}`,
      "# HELP sentinel_false_positives_total False positives",
      "# TYPE sentinel_false_positives_total counter",
      `sentinel_false_positives_total ${m.falsePositives}`,
      "# HELP sentinel_llm_calls_total LLM calls",
      "# TYPE sentinel_llm_calls_total counter",
      `sentinel_llm_calls_total ${m.llmCalls}`,
      "# HELP sentinel_llm_cost_usd_total Estimated LLM USD cost",
      "# TYPE sentinel_llm_cost_usd_total counter",
      `sentinel_llm_cost_usd_total ${m.llmCostUsd.toFixed(8)}`,
      "# HELP sentinel_scan_confidence_avg Average confidence",
      "# TYPE sentinel_scan_confidence_avg gauge",
      `sentinel_scan_confidence_avg ${m.avgConfidence.toFixed(6)}`,
      "# HELP sentinel_scan_latency_ms_avg Average scan latency in ms",
      "# TYPE sentinel_scan_latency_ms_avg gauge",
      `sentinel_scan_latency_ms_avg ${m.avgLatencyMs.toFixed(4)}`,
      "# HELP sentinel_scan_latency_ms_p50 P50 scan latency in ms",
      "# TYPE sentinel_scan_latency_ms_p50 gauge",
      `sentinel_scan_latency_ms_p50 ${m.p50LatencyMs.toFixed(4)}`,
      "# HELP sentinel_scan_latency_ms_p95 P95 scan latency in ms",
      "# TYPE sentinel_scan_latency_ms_p95 gauge",
      `sentinel_scan_latency_ms_p95 ${m.p95LatencyMs.toFixed(4)}`,
      "# HELP sentinel_scan_latency_ms_p99 P99 scan latency in ms",
      "# TYPE sentinel_scan_latency_ms_p99 gauge",
      `sentinel_scan_latency_ms_p99 ${m.p99LatencyMs.toFixed(4)}`,
      "",
    ].join("\n");
  }

  private percentile(p: number): number {
    if (this.latencies.length === 0) return 0;
    const sorted = [...this.latencies].sort((a, b) => a - b);
    const idx = Math.round((p / 100) * (sorted.length - 1));
    return sorted[Math.max(0, Math.min(idx, sorted.length - 1))];
  }
}

export class AuditTrail {
  constructor(private readonly enabled = false) {}

  append(event: Record<string, unknown>): void {
    if (!this.enabled) return;
    const safe = { ...event };
    delete safe.content;
    console.log(JSON.stringify({ timestamp: new Date().toISOString(), ...safe }));
  }
}
