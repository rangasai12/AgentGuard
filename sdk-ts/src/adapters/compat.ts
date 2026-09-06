/**
 * Shared helper for the openai/anthropic adapters: both SDKs' tool-call
 * objects can appear either as plain objects (raw API JSON) or as SDK
 * instances, depending on version and call site. This reads either shape
 * without requiring either SDK as a dependency.
 */
export function getField<T = unknown>(obj: unknown, key: string): T | undefined {
  if (obj && typeof obj === "object") {
    return (obj as Record<string, T>)[key];
  }
  return undefined;
}
