/**
 * Outbound paging for the safety watchers.
 *
 * Configure any subset; every configured sink gets every alert:
 *   DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
 *   TELEGRAM_BOT_TOKEN=123:abc  TELEGRAM_CHAT_ID=-1001234567890
 *   ALERT_WEBHOOK_URL=https://any/endpoint     (raw JSON POST)
 *
 * Never throws: a broken pager must not take the watcher down.
 */
const DISCORD = process.env.DISCORD_WEBHOOK_URL ?? "";
const TG_TOKEN = process.env.TELEGRAM_BOT_TOKEN ?? "";
const TG_CHAT = process.env.TELEGRAM_CHAT_ID ?? "";
const GENERIC = process.env.ALERT_WEBHOOK_URL ?? "";
const SOURCE = process.env.ALERT_SOURCE ?? "inazuma";

export const alertSinks = () =>
  [DISCORD && "discord", TG_TOKEN && TG_CHAT && "telegram", GENERIC && "webhook"].filter(Boolean);

const post = (url, body, headers = { "content-type": "application/json" }) =>
  fetch(url, { method: "POST", headers, body: JSON.stringify(body), signal: AbortSignal.timeout(8000) })
    .then((r) => r.ok || Promise.reject(new Error(`sink ${r.status}`)))
    .catch((e) => console.error(`[alert] sink failed: ${e.message}`));

/** kind: short machine tag, detail: human text, severity: critical|warning */
export async function page(kind, detail, severity = "critical") {
  const at = new Date().toISOString();
  const text = `${severity === "critical" ? "🚨" : "⚠️"} [${SOURCE}] ${kind}\n${detail}\n${at}`;
  const jobs = [];
  if (DISCORD) jobs.push(post(DISCORD, { content: text.slice(0, 1900) }));
  if (TG_TOKEN && TG_CHAT)
    jobs.push(post(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, { chat_id: TG_CHAT, text }));
  if (GENERIC) jobs.push(post(GENERIC, { source: SOURCE, kind, detail, severity, at }));
  if (jobs.length === 0) return false;
  await Promise.allSettled(jobs);
  return true;
}
