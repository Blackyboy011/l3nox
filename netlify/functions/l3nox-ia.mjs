// Service IA de L3NOX : rédige le « Briefing du jour » avec l'IA de Netlify (AI Gateway).
// Les crédits gratuits du compte Netlify sont utilisés ; aucune clé payante n'est nécessaire.
// Protégé par un mot de passe partagé (variable Netlify L3NOX_AI_SECRET).

const MODELS = ["claude-haiku-5-5", "claude-haiku-4-5"]; // modèles autorisés (les plus économes)

export default async (req) => {
  if (req.method !== "POST") {
    return new Response("Service IA de L3NOX : rien à voir ici.", { status: 405 });
  }
  const secret = process.env.L3NOX_AI_SECRET;
  if (!secret || req.headers.get("x-l3nox-secret") !== secret) {
    return new Response("Accès refusé", { status: 403 });
  }
  let body;
  try {
    body = await req.json();
  } catch {
    return new Response("Requête invalide", { status: 400 });
  }
  const model = MODELS.includes(body.model) ? body.model : MODELS[0];
  const maxTokens = Math.min(Number(body.max_tokens) || 3500, 4000);
  const prompt = String(body.prompt || "").slice(0, 60000);
  const system = String(body.system || "").slice(0, 8000);
  const base = (process.env.ANTHROPIC_BASE_URL || "https://api.anthropic.com").replace(/\/$/, "");
  const key = process.env.ANTHROPIC_API_KEY;

  // Réponse « en flux » : la rédaction peut prendre jusqu'à une minute.
  const enc = new TextEncoder();
  const stream = new ReadableStream({
    async start(ctrl) {
      ctrl.enqueue(enc.encode(" "));
      const ping = setInterval(() => ctrl.enqueue(enc.encode(" ")), 5000);
      try {
        const r = await fetch(`${base}/v1/messages`, {
          method: "POST",
          headers: { "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json" },
          body: JSON.stringify({ model, max_tokens: maxTokens, system, messages: [{ role: "user", content: prompt }] }),
        });
        const j = await r.json();
        if (!r.ok) throw new Error(j?.error?.message || `erreur ${r.status}`);
        const text = (j.content || []).filter((b) => b.type === "text").map((b) => b.text).join("");
        ctrl.enqueue(enc.encode(JSON.stringify({ text, usage: j.usage, model })));
      } catch (e) {
        ctrl.enqueue(enc.encode(JSON.stringify({ error: String(e?.message || e) })));
      } finally {
        clearInterval(ping);
        ctrl.close();
      }
    },
  });
  return new Response(stream, { headers: { "content-type": "application/json; charset=utf-8" } });
};

export const config = { path: "/api/ia" };
