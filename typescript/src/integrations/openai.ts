/**
 * OpenAI integration for sentinel-inject.
 *
 * Screens tool call results before they enter the agent context.
 *
 * @example
 * import OpenAI from "openai";
 * import { wrapOpenAIClient } from "sentinel-inject/integrations/openai";
 *
 * const client = wrapOpenAIClient(new OpenAI({ apiKey: "sk-..." }));
 *
 * // Tool result messages are automatically screened
 * const response = await client.chat.completions.create({
 *   model: "gpt-4o",
 *   messages: [
 *     { role: "tool", tool_call_id: "call_abc", content: toolOutput },
 *   ],
 * });
 */

import { Middleware, MiddlewareConfig } from "../middleware";
import { SanitizationMode } from "../sanitizer";

export interface OpenAIToolMessage {
  role: "tool";
  tool_call_id: string;
  content: string;
  [key: string]: unknown;
}

export type ChatMessage =
  | OpenAIToolMessage
  | { role: string; content?: string; [key: string]: unknown };

/**
 * Screen a list of OpenAI tool call result messages.
 *
 * Returns a new array with potentially sanitized content.
 */
export async function screenToolCallResults(
  toolResults: ChatMessage[],
  middleware?: Middleware
): Promise<ChatMessage[]> {
  const mw = middleware ?? new Middleware();
  const screened: ChatMessage[] = [];

  for (const msg of toolResults) {
    if (msg.role !== "tool") {
      screened.push(msg);
      continue;
    }

    const toolMsg = msg as OpenAIToolMessage;
    const safeContent = await mw.processToolResult(
      toolMsg.content,
      `openai_tool:${toolMsg.tool_call_id}`,
      { tool_call_id: toolMsg.tool_call_id }
    );

    screened.push({ ...toolMsg, content: safeContent });
  }

  return screened;
}

/**
 * Wraps an OpenAI client to automatically screen tool result messages.
 *
 * All messages with `role: "tool"` in the messages array are screened
 * before the request is sent to the API.
 */
export function wrapOpenAIClient(
  client: any,
  options: {
    middleware?: Middleware;
    sanitizationMode?: SanitizationMode;
  } = {}
): any {
  const mw =
    options.middleware ??
    new Middleware(undefined, {
      sanitizationMode: options.sanitizationMode ?? SanitizationMode.LABEL,
    });

  const originalCreate = client.chat.completions.create.bind(
    client.chat.completions
  );

  client.chat.completions.create = async (params: any, ...rest: any[]) => {
    const messages: ChatMessage[] = params.messages ?? [];
    const safeMessages = await screenToolCallResults(messages, mw);
    return originalCreate({ ...params, messages: safeMessages }, ...rest);
  };

  return client;
}
