import type { CanonicalAlert } from "../types.ts";

const TEN_MINUTES_MS = 10 * 60 * 1000;

function parseAlertTime(ts: string | null): number | null {
  if (!ts) return null;
  const parsed = Date.parse(ts);
  return Number.isNaN(parsed) ? null : parsed;
}

/**
 * Deterministic aggregation: collapses alerts with the same (rule_id + agent + source_ip)
 * within a 10-minute window into one item with a collapsed_count.
 */
export function aggregateAlerts(alerts: CanonicalAlert[]): CanonicalAlert[] {
  const result: CanonicalAlert[] = [];

  for (const item of alerts) {
    const ruleKey = (item.rule_id ?? "").trim().toLowerCase();
    const agentKey = (item.agent_name ?? item.agent_ip ?? "").trim().toLowerCase();
    const srcKey = (item.source_ip ?? "").trim().toLowerCase();

    // Require at least rule_id and (agent or source_ip) to avoid collapsing unrelated empty alerts
    const canAggregate = Boolean(ruleKey && (agentKey || srcKey));
    if (!canAggregate) {
      result.push({
        ...item,
        collapsed_count: item.collapsed_count ?? 1,
      });
      continue;
    }

    const itemTime = parseAlertTime(item.timestamp);
    let matchedIdx = -1;

    for (let i = result.length - 1; i >= 0; i -= 1) {
      const existing = result[i];
      const exRule = (existing.rule_id ?? "").trim().toLowerCase();
      const exAgent = (existing.agent_name ?? existing.agent_ip ?? "")
        .trim()
        .toLowerCase();
      const exSrc = (existing.source_ip ?? "").trim().toLowerCase();

      if (exRule === ruleKey && exAgent === agentKey && exSrc === srcKey) {
        const exTime = parseAlertTime(existing.timestamp);
        if (itemTime !== null && exTime !== null) {
          if (Math.abs(itemTime - exTime) <= TEN_MINUTES_MS) {
            matchedIdx = i;
            break;
          }
        } else if (itemTime === null && exTime === null) {
          matchedIdx = i;
          break;
        }
      }
    }

    if (matchedIdx >= 0) {
      const existing = result[matchedIdx];
      const prevCount = existing.collapsed_count ?? 1;
      const addCount = item.collapsed_count ?? 1;
      result[matchedIdx] = {
        ...existing,
        collapsed_count: prevCount + addCount,
      };
    } else {
      result.push({
        ...item,
        collapsed_count: item.collapsed_count ?? 1,
      });
    }
  }

  return result;
}
