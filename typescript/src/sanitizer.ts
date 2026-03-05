/**
 * Sanitizer - neutralizes detected prompt injection attempts.
 */

export enum SanitizationMode {
  /** Wrap suspicious content with a visible warning label */
  LABEL = "label",
  /** Replace matched injection segments with [REDACTED] */
  REDACT = "redact",
  /** Escape injection syntax to defuse while keeping context */
  ESCAPE = "escape",
  /** Return a placeholder; do NOT pass any content through */
  BLOCK = "block",
}

const LABEL_PREFIX = "[⚠ SENTINEL: POSSIBLE INJECTION DETECTED] ";
const LABEL_SUFFIX = " [/SENTINEL]";

const BLOCK_MESSAGE =
  "[SENTINEL] This content was blocked because it contains a detected " +
  "prompt injection attempt and cannot be passed to the agent context.";

type EscapePattern = [RegExp, string];

const ESCAPE_PATTERNS: EscapePattern[] = [
  // Remove zero-width / invisible characters
  [/[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00ad]/g, ""],
  // Neutralize delimiter markers
  [/<\|?(system|user|assistant|im_start|im_end)\|?>/gi, "[$1]"],
  [/\[INST\]|\[\/INST\]/gi, "[inst]"],
  [/<<SYS>>|<\/SYS>>/gi, "<<sys>>"],
  // Defuse script tags
  [/<script/gi, "&lt;script"],
  [/<\/script>/gi, "&lt;/script&gt;"],
  // Neutralize instruction overrides
  [
    /\b(ignore|disregard|forget|override)(\b.{0,30}\b)(previous|prior|above|all|system)(\b.{0,30}\b)(instructions?|prompts?|context|rules?)\b/gis,
    "[NEUTRALIZED:$1$2$3$4$5]",
  ],
];

const REDACT_PATTERNS: RegExp[] = [
  /\b(ignore|disregard|forget|override|bypass)\b.{0,60}\b(instructions?|prompts?|context|rules?)\b/gis,
  /(```\s*(system|user|assistant)\b.*?```|<\|?(system|user|assistant|im_start|im_end)\|?>.*?<\|?im_end\|?>)/gis,
];

export class Sanitizer {
  constructor(public mode: SanitizationMode = SanitizationMode.LABEL) {}

  sanitize(
    content: string,
    matchSpans?: Array<[number, number]>
  ): string {
    switch (this.mode) {
      case SanitizationMode.BLOCK:
        return BLOCK_MESSAGE;
      case SanitizationMode.LABEL:
        return this.label(content);
      case SanitizationMode.ESCAPE:
        return this.escape(content);
      case SanitizationMode.REDACT:
        return this.redact(content, matchSpans);
      default:
        return content;
    }
  }

  private label(content: string): string {
    return `${LABEL_PREFIX}${content}${LABEL_SUFFIX}`;
  }

  private escape(content: string): string {
    let result = content;
    for (const [pattern, replacement] of ESCAPE_PATTERNS) {
      result = result.replace(pattern, replacement);
    }
    return result;
  }

  private redact(
    content: string,
    matchSpans?: Array<[number, number]>
  ): string {
    if (matchSpans && matchSpans.length > 0) {
      const sorted = [...matchSpans].sort((a, b) => a[0] - b[0]);
      const parts: string[] = [];
      let cursor = 0;
      for (const [start, end] of sorted) {
        parts.push(content.slice(cursor, start));
        parts.push("[REDACTED]");
        cursor = end;
      }
      parts.push(content.slice(cursor));
      return parts.join("");
    }

    let result = content;
    for (const pattern of REDACT_PATTERNS) {
      result = result.replace(pattern, "[REDACTED]");
    }
    return result;
  }

  static stripZeroWidth(text: string): string {
    return text.replace(/[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00ad]/g, "");
  }

  static normalizeWhitespace(text: string): string {
    return text.replace(/[ \t]{3,}/g, " ").trim();
  }
}
