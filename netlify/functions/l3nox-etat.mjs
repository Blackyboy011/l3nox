// Synchronisation des choix « Valider / Pas concerné » de L3NOX entre les appareils du propriétaire.
// Protégé par un code personnel (variable Netlify L3NOX_SYNC_CODE). Les autres visiteurs n'y ont pas accès :
// leurs choix restent dans leur propre navigateur.
import { getStore } from "@netlify/blobs";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, PUT, OPTIONS",
  "Access-Control-Allow-Headers": "content-type, x-l3nox-code",
  "Access-Control-Max-Age": "86400",
};
const KEEP_DAYS = 150;
const MAX_ITEMS = 3000;

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { ...CORS, "content-type": "application/json; charset=utf-8" } });

export default async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

  const code = process.env.L3NOX_SYNC_CODE;
  if (!code || req.headers.get("x-l3nox-code") !== code) return json({ error: "code incorrect" }, 403);

  const store = getStore("l3nox-etat");
  const current = ((await store.get("choix", { type: "json" })) || {}).items || {};

  if (req.method === "GET") return json({ items: current });

  if (req.method === "PUT") {
    let body;
    try {
      body = await req.json();
    } catch {
      return json({ error: "requête invalide" }, 400);
    }
    const incoming = body && typeof body.items === "object" && body.items ? body.items : {};
    // Fusion : pour chaque alerte, le choix le plus récent l'emporte.
    for (const [id, v] of Object.entries(incoming)) {
      if (!v || typeof v.t !== "number" || String(id).length > 300) continue;
      const s = ["done", "hidden", ""].includes(v.s) ? v.s : "";
      if (!current[id] || current[id].t < v.t) current[id] = { s, t: v.t };
    }
    const limit = Date.now() - KEEP_DAYS * 864e5;
    const ids = Object.keys(current)
      .filter((id) => current[id].t >= limit)
      .sort((a, b) => current[b].t - current[a].t)
      .slice(0, MAX_ITEMS);
    const items = Object.fromEntries(ids.map((id) => [id, current[id]]));
    await store.setJSON("choix", { items, updated: Date.now() });
    return json({ items });
  }

  return json({ error: "méthode non autorisée" }, 405);
};

export const config = { path: "/api/etat" };
