/**
 * Rule-based detection engine for prompt injection attempts.
 *
 * Detects known injection patterns using regex, keyword matching,
 * structural heuristics, and threat signature databases.
 */

export enum RuleSeverity {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical",
}

export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: RuleSeverity;
  pattern?: RegExp;
  keywords?: string[];
  enabled: boolean;
}

export interface RuleMatch {
  ruleId: string;
  ruleName: string;
  severity: RuleSeverity;
  matchedText: string;
  start: number;
  end: number;
  description: string;
}

export function severityScore(severity: RuleSeverity): number {
  const scores: Record<RuleSeverity, number> = {
    [RuleSeverity.LOW]: 0.25,
    [RuleSeverity.MEDIUM]: 0.5,
    [RuleSeverity.HIGH]: 0.75,
    [RuleSeverity.CRITICAL]: 1.0,
  };
  return scores[severity];
}

// ---------------------------------------------------------------------------
// Built-in rules
// ---------------------------------------------------------------------------

const BUILTIN_RULES: Rule[] = [
  {
    id: "PI-001",
    name: "Instruction Override Attempt",
    description: "Explicit instruction to ignore or override system/previous instructions",
    severity: RuleSeverity.CRITICAL,
    pattern:
      /\b(ignore|disregard|forget|override|bypass|skip|cancel|undo|reset)\b.{0,40}\b(previous|prior|above|all|system|original|earlier)\b.{0,40}\b(instructions?|prompts?|context|rules?|constraints?|guidelines?)\b/gis,
    enabled: true,
  },
  {
    id: "PI-002",
    name: "New Instructions Injection",
    description: "Attempts to inject new directive instructions mid-content",
    severity: RuleSeverity.HIGH,
    pattern: /\b(new|actual|real|true|hidden|secret)\b.{0,30}\b(instructions?|directives?|commands?|orders?)\b[\s:]+/gi,
    enabled: true,
  },
  {
    id: "PI-003",
    name: "Role Reassignment",
    description: "Attempts to reassign the AI's role or persona",
    severity: RuleSeverity.HIGH,
    pattern:
      /\b(you are|you're|act as|pretend (to be|you are)|roleplay as|behave as|your (new |true |real )?role is|from now on you)\b/gi,
    enabled: true,
  },
  {
    id: "PI-004",
    name: "DAN / Jailbreak Persona",
    description: "Known jailbreak persona names",
    severity: RuleSeverity.CRITICAL,
    keywords: [
      "DAN",
      "Do Anything Now",
      "STAN",
      "DUDE",
      "Mongo Tom",
      "AIM",
      "Developer Mode",
      "jailbreak mode",
      "unrestricted mode",
      "evil mode",
      "no-filter mode",
      "god mode",
    ],
    enabled: true,
  },
  {
    id: "PI-005",
    name: "System Prompt Extraction",
    description: "Attempts to extract or reveal the system prompt",
    severity: RuleSeverity.HIGH,
    pattern:
      /\b(repeat|print|show|reveal|output|display|tell me|share|leak|expose|dump)\b.{0,60}\b(system prompt|system message|instructions?|context|initial prompt|original prompt|hidden prompt|base prompt)\b/gis,
    enabled: true,
  },
  {
    id: "PI-006",
    name: "Delimiter Injection",
    description: "Injection using common prompt delimiters to break context",
    severity: RuleSeverity.HIGH,
    pattern:
      /(```\s*(system|user|assistant|human|AI)\b|<\|?(system|user|assistant|im_start|im_end)\|?>|\[INST\]|\[\/INST\]|###\s*(System|Human|Assistant|Instruction)|\[SYSTEM\]|\[USER\]|\[ASSISTANT\]|<<SYS>>|<\/SYS>>)/gi,
    enabled: true,
  },
  {
    id: "PI-007",
    name: "Markdown/HTML Context Escape",
    description: "Attempts to escape context using markdown or HTML tricks",
    severity: RuleSeverity.MEDIUM,
    pattern: /(<script[\s>]|<\/script>|javascript:|data:text\/html|<!--.*?-->|<iframe|<object|<embed)/gis,
    enabled: true,
  },
  {
    id: "PI-008",
    name: "Indirect Injection Marker",
    description: "Content that appears to be injected via external sources",
    severity: RuleSeverity.MEDIUM,
    pattern: /\b(attention|note|important|warning|alert)\s*[:!]\s*(ai|llm|gpt|claude|gemini|assistant|model|bot)\b/gi,
    enabled: true,
  },
  {
    id: "PI-009",
    name: "Hidden Text Injection",
    description: "Zero-width characters or CSS tricks to hide injected text",
    severity: RuleSeverity.HIGH,
    pattern:
      /[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00ad]|color\s*:\s*(white|#fff|#ffffff|rgba?\(255,255,255)|font-size\s*:\s*0/gi,
    enabled: true,
  },
  {
    id: "PI-010",
    name: "Privilege Escalation",
    description: "Attempts to gain elevated permissions or access",
    severity: RuleSeverity.HIGH,
    pattern:
      /\b(sudo|root access|admin mode|administrator|superuser|elevated privileges?|unrestricted access|full access|disable (safety|filter|restriction|guardrail)s?)\b/gi,
    enabled: true,
  },
  {
    id: "PI-011",
    name: "Exfiltration Command",
    description: "Instructions to send data to external locations",
    severity: RuleSeverity.CRITICAL,
    pattern:
      /\b(send|transmit|upload|post|forward|email|relay|exfiltrate)\b.{0,60}\b(to|via)\b.{0,60}(https?:\/\/|ftp:\/\/|smtp:\/\/|webhook|endpoint|server|url|api)/gis,
    enabled: true,
  },
  {
    id: "PI-012",
    name: "Task Completion Hijack",
    description: "Injected content pretending the task is done",
    severity: RuleSeverity.MEDIUM,
    pattern:
      /\b(task (complete|done|finished|accomplished)|you have (successfully|now)|mission accomplished|proceed to (the next|your next|step))\b/gi,
    enabled: true,
  },
  {
    id: "PI-013",
    name: "Encoded Payload",
    description: "Base64 or encoded content that may contain hidden instructions",
    severity: RuleSeverity.MEDIUM,
    pattern: /\b(decode|base64|rot13|hex decode|url decode|eval|exec)\s*[(:\"']/gi,
    enabled: true,
  },
  {
    id: "PI-014",
    name: "Language Switch Attack",
    description: "Switches language to bypass content filters",
    severity: RuleSeverity.LOW,
    pattern:
      /\b(translate (this )?to|in (french|spanish|german|chinese|arabic|russian|japanese))\b.{0,80}\b(ignore|bypass|forbidden|restricted|not allowed)\b/gis,
    enabled: true,
  },
  {
    id: "PI-015",
    name: "Simulation Framing",
    description: "Frames malicious instructions as hypothetical or simulated",
    severity: RuleSeverity.MEDIUM,
    pattern:
      /\b(hypothetically|theoretically|for (educational|research|training) purposes?|in a (simulation|fictional|story|game|scenario)|imagine (you are|that you|if you)|as a (thought experiment|exercise|test))\b/gi,
    enabled: true,
  },
];

// ---------------------------------------------------------------------------
// RuleEngine
// ---------------------------------------------------------------------------

export class RuleEngine {
  private _rules: Rule[];

  constructor(customRules?: Rule[]) {
    // Deep-clone builtins so instances are independent
    this._rules = BUILTIN_RULES.map((r) => ({ ...r }));
    if (customRules) {
      this._rules.push(...customRules);
    }
  }

  addRule(rule: Rule): void {
    this._rules.push(rule);
  }

  removeRule(ruleId: string): boolean {
    const before = this._rules.length;
    this._rules = this._rules.filter((r) => r.id !== ruleId);
    return this._rules.length < before;
  }

  disableRule(ruleId: string): boolean {
    const rule = this._rules.find((r) => r.id === ruleId);
    if (rule) {
      rule.enabled = false;
      return true;
    }
    return false;
  }

  enableRule(ruleId: string): boolean {
    const rule = this._rules.find((r) => r.id === ruleId);
    if (rule) {
      rule.enabled = true;
      return true;
    }
    return false;
  }

  scan(text: string): RuleMatch[] {
    const matches: RuleMatch[] = [];

    for (const rule of this._rules) {
      if (!rule.enabled) continue;

      if (rule.pattern) {
        // Reset lastIndex for global patterns
        rule.pattern.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = rule.pattern.exec(text)) !== null) {
          matches.push({
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            matchedText: m[0],
            start: m.index,
            end: m.index + m[0].length,
            description: rule.description,
          });
          // Prevent infinite loops on zero-length matches
          if (m[0].length === 0) {
            rule.pattern.lastIndex++;
          }
        }
        rule.pattern.lastIndex = 0;
      } else if (rule.keywords) {
        for (const kw of rule.keywords) {
          // Use word-boundary regex for accurate keyword matching
          const kwPattern = new RegExp(
            `\\b${kw.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`,
            "i"
          );
          const m = kwPattern.exec(text);
          if (m) {
            matches.push({
              ruleId: rule.id,
              ruleName: rule.name,
              severity: rule.severity,
              matchedText: m[0],
              start: m.index,
              end: m.index + m[0].length,
              description: rule.description,
            });
            break; // one match per keyword rule
          }
        }
      }
    }

    return matches;
  }

  get rules(): Rule[] {
    return [...this._rules];
  }

  get activeRuleCount(): number {
    return this._rules.filter((r) => r.enabled).length;
  }
}
