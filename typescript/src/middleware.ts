/**
 * Middleware - drop-in wrappers for tool results and user input.
 */

import { Scanner, ScanResult, ThreatLevel } from "./scanner";
import { SanitizationMode } from "./sanitizer";

export class InjectionDetectedError extends Error {
  constructor(public readonly scanResult: ScanResult) {
    super(
      `Prompt injection detected (confidence=${Math.round(scanResult.confidence * 100)}%, ` +
        `level=${scanResult.threatLevel})`
    );
    this.name = "InjectionDetectedError";
  }
}

export interface MiddlewareConfig {
  sanitizationMode?: SanitizationMode;
  /** Block content entirely instead of passing sanitized version */
  blockOnThreat?: boolean;
  blockMessage?: string;
  /** Throw InjectionDetectedError when threat is found */
  raiseOnThreat?: boolean;
  /** Sources considered high-risk (always force careful scanning) */
  highRiskSources?: string[];
  /** Whether to scan user input */
  scanUserInput?: boolean;
  /** Force LLM detection for high-risk sources */
  forceLlmForHighRisk?: boolean;
}

export class Middleware {
  private scanner: Scanner;
  private config: Required<MiddlewareConfig>;
  private _scanHistory: ScanResult[] = [];

  constructor(scanner?: Scanner, config?: MiddlewareConfig) {
    this.config = {
      sanitizationMode: config?.sanitizationMode ?? SanitizationMode.LABEL,
      blockOnThreat: config?.blockOnThreat ?? false,
      blockMessage:
        config?.blockMessage ??
        "[SENTINEL] Content blocked: prompt injection attempt detected.",
      raiseOnThreat: config?.raiseOnThreat ?? false,
      highRiskSources: config?.highRiskSources ?? [
        "web_fetch",
        "browser",
        "file_read",
        "url",
      ],
      scanUserInput: config?.scanUserInput ?? true,
      forceLlmForHighRisk: config?.forceLlmForHighRisk ?? true,
    };

    this.scanner =
      scanner ??
      new Scanner({ sanitizationMode: this.config.sanitizationMode });
  }

  async processToolResult(
    content: string,
    toolName = "unknown",
    metadata: Record<string, unknown> = {}
  ): Promise<string> {
    const isHighRisk = this.config.highRiskSources.some((s) =>
      toolName.toLowerCase().includes(s)
    );
    const forceLlm = this.config.forceLlmForHighRisk && isHighRisk;

    const result = await this.scanner.scan(
      content,
      { source: "tool_result", toolName, ...metadata },
      forceLlm
    );
    this._scanHistory.push(result);
    return this.handleResult(result, content);
  }

  async processUserInput(
    content: string,
    userId?: string,
    metadata: Record<string, unknown> = {}
  ): Promise<string> {
    if (!this.config.scanUserInput) return content;

    const result = await this.scanner.scan(content, {
      source: "user_input",
      userId,
      ...metadata,
    });
    this._scanHistory.push(result);
    return this.handleResult(result, content);
  }

  async processWebContent(
    content: string,
    url?: string,
    metadata: Record<string, unknown> = {}
  ): Promise<string> {
    const result = await this.scanner.scan(
      content,
      { source: "web_content", url, ...metadata },
      true // always force LLM for web content
    );
    this._scanHistory.push(result);
    return this.handleResult(result, content);
  }

  async processDocument(
    content: string,
    docName?: string,
    metadata: Record<string, unknown> = {}
  ): Promise<string> {
    const result = await this.scanner.scan(content, {
      source: "document",
      docName,
      ...metadata,
    });
    this._scanHistory.push(result);
    return this.handleResult(result, content);
  }

  async scan(
    content: string,
    metadata?: Record<string, unknown>
  ): Promise<ScanResult> {
    return this.scanner.scan(content, metadata ?? {});
  }

  /**
   * Higher-order function that wraps any async function to screen its string output.
   *
   * @example
   * const safeFetch = mw.wrapTool("web_fetch", async (url: string) => {
   *   return fetch(url).then(r => r.text());
   * });
   */
  wrapTool<TArgs extends unknown[], TReturn>(
    toolName: string,
    fn: (...args: TArgs) => Promise<TReturn>
  ): (...args: TArgs) => Promise<TReturn> {
    return async (...args: TArgs): Promise<TReturn> => {
      const result = await fn(...args);
      if (typeof result === "string") {
        return (await this.processToolResult(result, toolName)) as TReturn;
      }
      return result;
    };
  }

  get scanHistory(): ScanResult[] {
    return [...this._scanHistory];
  }

  get threatCount(): number {
    return this._scanHistory.filter((r) => r.isThreat).length;
  }

  clearHistory(): void {
    this._scanHistory = [];
  }

  private handleResult(result: ScanResult, original: string): string {
    if (!result.isThreat) return original;

    if (this.config.raiseOnThreat) {
      throw new InjectionDetectedError(result);
    }

    if (this.config.blockOnThreat) {
      return this.config.blockMessage;
    }

    return result.sanitizedContent ?? original;
  }
}
