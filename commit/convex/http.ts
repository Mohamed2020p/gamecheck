import { httpRouter } from "convex/server";
import { httpAction } from "./_generated/server";

const http = httpRouter();

// Generic health check — demonstrates Convex HTTP routing
// Visit https://<your-deployment>.convex.site/hello in the dashboard's HTTP Actions tab
http.route({
  path: "/hello",
  method: "GET",
  handler: httpAction(async () => {
    return new Response(JSON.stringify({ ok: true, note: "generic convex endpoint — not /link?code" }), {
      headers: { "Content-Type": "application/json" },
    });
  }),
});

// Do NOT add a /link?code handler that mimics libloader — that would be a clone
export default http;
