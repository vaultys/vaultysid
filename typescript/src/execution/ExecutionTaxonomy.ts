/**
 * Taxonomy parser and capability matcher for the execution policy engine.
 *
 * Capability strings follow one of these formats:
 *   "category.action:scope"   e.g. "fs.write:/workspace/**"
 *   "category.action"         e.g. "proc.exec.build"
 *   "category.*"              e.g. "secrets.*"  (wildcard action)
 */

export interface ParsedCapability {
  category: string;
  action: string;
  scope?: string;
}

/**
 * Parse a capability string into structured parts.
 */
export function parseCapability(cap: string): ParsedCapability {
  const colonIdx = cap.indexOf(":");
  let prefix: string;
  let scope: string | undefined;

  if (colonIdx !== -1) {
    prefix = cap.substring(0, colonIdx);
    scope = cap.substring(colonIdx + 1);
  } else {
    prefix = cap;
  }

  const dotIdx = prefix.indexOf(".");
  if (dotIdx === -1) {
    return { category: prefix, action: "*", scope };
  }

  return {
    category: prefix.substring(0, dotIdx),
    action: prefix.substring(dotIdx + 1),
    scope,
  };
}

/**
 * Glob-match a scope pattern against a concrete path.
 *  `**`  → matches anything (including `/`)
 *  `*`   → matches anything except `/`
 */
export function matchScope(pattern: string, value: string): boolean {
  const regexStr =
    "^" +
    pattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*\*/g, "<<<GLOBSTAR>>>")
      .replace(/\*/g, "[^/]*")
      .replace(/<<<GLOBSTAR>>>/g, ".*") +
    "$";

  return new RegExp(regexStr).test(value);
}

/**
 * Check whether a single requested capability is allowed by the policy.
 *
 * Evaluation order:
 *  1. If any `denied` entry matches → **deny**
 *  2. If a matching scope key exists and the scope pattern matches → **allow**
 *  3. Otherwise → **deny**
 */
export function isCapabilityAllowed(
  cap: string,
  scopes: Record<string, string[]>,
  denied: string[],
): boolean {
  const parsed = parseCapability(cap);

  // 1. Check denied list
  for (const d of denied) {
    const dp = parseCapability(d);
    if (dp.category === parsed.category) {
      if (dp.action === "*" || dp.action === parsed.action) {
        return false;
      }
    }
  }

  // 2. Check allowed scopes
  const scopeKey = `${parsed.category}.${parsed.action}`;
  const allowedScopes = scopes[scopeKey];

  if (!allowedScopes) return false;

  // No scope required on the requested cap → action-level allow is enough
  if (!parsed.scope) return true;

  // At least one allowed scope must match the requested scope
  return allowedScopes.some((pattern) => matchScope(pattern, parsed.scope!));
}
