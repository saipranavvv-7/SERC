import { GoogleGenAI } from "@google/genai";

let cachedClient: GoogleGenAI | null = null;

export function getGeminiClient(): GoogleGenAI {
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  if (!apiKey || apiKey === "MY_GEMINI_API_KEY") {
    throw new Error(
      "GEMINI_API_KEY is not configured. Add a valid key in Settings > Secrets."
    );
  }
  if (!cachedClient) {
    cachedClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  }
  return cachedClient;
}

export function formatGeminiError(err: unknown): string {
  if (err instanceof Error) {
    const msg = err.message || "Unknown Gemini API error";
    if (msg.includes("API_KEY_INVALID") || msg.includes("400")) {
      return `Gemini API error (400/Invalid request or API key): ${msg}`;
    }
    if (msg.includes("PERMISSION_DENIED") || msg.includes("403")) {
      return `Gemini API permission denied (403). Check GEMINI_API_KEY in Settings > Secrets. (${msg})`;
    }
    if (msg.includes("RESOURCE_EXHAUSTED") || msg.includes("429")) {
      return `Gemini API rate limit / quota exceeded (429): ${msg}`;
    }
    if (msg.includes("NOT_FOUND") || msg.includes("404")) {
      return `Gemini model not found (404): ${msg}`;
    }
    return msg;
  }
  return String(err);
}

export function isRateLimitError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return (
    msg.includes("429") ||
    msg.includes("RESOURCE_EXHAUSTED") ||
    msg.toLowerCase().includes("rate limit") ||
    msg.toLowerCase().includes("quota")
  );
}

export async function withRetry429<T>(
  fn: () => Promise<T>,
  maxRetries = 4,
  baseDelayMs = 1200
): Promise<T> {
  let attempt = 0;
  while (true) {
    try {
      return await fn();
    } catch (err) {
      if (isRateLimitError(err) && attempt < maxRetries) {
        const delay = baseDelayMs * Math.pow(2, attempt) + Math.floor(Math.random() * 250);
        attempt += 1;
        await new Promise((resolve) => setTimeout(resolve, delay));
        continue;
      }
      throw err;
    }
  }
}
