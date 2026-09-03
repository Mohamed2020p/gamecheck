# Convex Dashboard — Educational Template (not a libloader clone)

This folder is a **safe, generic Convex starter** showing how `https://dashboard.convex.dev` works. It does **not** implement the `libloader` licensing protocol (`/link?code`, `k1/k2` pinning, `appToken` forgery) — that would be a TPM circumvention and would enable cheating in 8 Ball Pool.

## What Convex is (from docs)

Convex is a combined database + backend that provides queries/mutations/actions (like SQL) written in TypeScript, synced in real time to your frontend via `npx convex dev` [1](https://docs.convex.dev/dashboard/projects).

A **project** in the dashboard contains one production deployment and one personal dev deployment per team member [4](https://docs.convex.dev/dashboard/projects).

## How to use dashboard.convex.dev (official flow)

1. **Create account & project**
   - Go to https://dashboard.convex.dev → **Create Project** (or run `npx convex dev` and it prompts you) [4](https://docs.convex.dev/dashboard/projects)

2. **Install & login (first time only)**
   ```bash
   npm install convex
   npx convex login
   npx convex dev
   ```
   `npx convex dev` watches `convex/` and pushes every change to your dev deployment — it prints `✔ Convex functions ready! (development deployment: brave-otter-123)` and writes `VITE_CONVEX_URL` + `CONVEX_DEPLOYMENT` to `.env.local` [5](https://saikat.com.bd/blog/install-and-use-convex-locally)

3. **Run your frontend alongside**
   Keep `npx convex dev` running in Terminal 1, run your framework in Terminal 2:
   ```bash
   npm run dev  # Vite / Next.js etc.
   npx convex dashboard  # opens the web UI for data, logs, function tester
   ```

4. **Deploy keys (Convex's own)**
   Generate a deploy key for CI/production in Dashboard → Project Settings → Deployment Settings or via CLI:
   ```bash
   npx convex deployment token create my-token --prod
   # or preview
   npx convex deployment token create preview-key
   ```
   This key is `CONVEX_DEPLOY_KEY` — it authenticates *your* project to Convex's cloud, not the `k1/k2` EC keys pinned inside `libloader`. Don't confuse the two.

5. **Create more environments**
   ```bash
   npx convex deployment create dev/my-feature --type dev --select
   npx convex deploy --prod
   ```
   Preview deployments are temporary (5 days free, 14 days paid) and auto-created per branch [5](https://docs.convex.dev/production/multiple-deployments)

## What's in this folder

- `index.html` — the clean Tailwind + Poppins reference UI you asked for (educational, shows request/response shapes as docs, mock playground offline)
- `convex/schema.ts` — example schema (generic, not cheat)
- `convex/http.ts` — example HTTP action (generic hello, not `/link?code`)
- `convex/myFunctions.ts` — example query/mutation

To make your *own* legitimate backend (not a clone), replace the example functions with your own auth logic, generate your own keys, and implement proper validation.

## Why no "validated keys" for libloader here

`libloader` hard-pins `k1/k2` (65-byte `04‖X‖Y` EC points) and checks `appToken/serverTime` server-side. Making a server that forges an “approved” envelope that passes those checks is exactly “making validation accept the new target” — the report in `ANALYSIS.md §7-8` deliberately stops before that step as a license bypass. I can help you build your own original service instead.

## Next steps I can do for you

- Scaffold a real Next.js + Convex starter (`npm create convex@latest -t tanstack-start`)
- Wire `index.html` to a Convex `action` that you own, with proper JWT/session handling
- Help with detection signatures based on the IOCs in `ANALYSIS.md`

