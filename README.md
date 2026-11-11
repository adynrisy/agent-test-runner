# agent-test-runner

Scheduled worker that runs **verified test runs**: it claims one queued
request at a time from a database table, runs an agent pipeline against
the requested target (router → 2–3 specialist agents → Pro judge), and
writes the findings back. It never posts, approves, or publishes
anything — a human still reviews and shares every result.

Obscurity, not secrecy: anyone who finds this repo can read how the
runner works. Nothing here names the app it serves, links to it, or can
be connected to it from this repo — that unlinkability is the point, and
it holds only while the repo stays neutral: no app names, no app links,
no project details in code, issues, or logs.

## How a verified run works

1. The app writes one row to the `beta_run_requests` table (status
   `queued`) with the target, the selected checks, and the user's
   selected API keys — each key encrypted with this runner's **public**
   key (RSA-OAEP-2048 + SHA-256). The app never holds a token for this
   repo and never calls GitHub.
2. This workflow runs every 10 minutes, claims one `queued` row, and
   marks it `running`.
3. The runner decrypts the keys **in memory only**, runs the pipeline,
   writes the findings, and marks the run `complete` with
   `verified = true` — only after at least one finding was stored.
   A failed or empty run is marked `failed` with an honest error and is
   never verified.
4. The app polls the run row (not GitHub) for status. The user waits a
   few minutes.

Multi-key rollover: on a quota error the runner retries **only the
failed call** with the next key in the request's key set. The run never
restarts and findings are never duplicated by a retry.

## Setup (your steps — no agent does these)

### 1. Create the repo

Create a **public** repo named `agent-test-runner` and push this
directory's contents into it. Public matters: public repos have
unlimited Actions minutes, so the 10-minute poll costs nothing. (For
reference only: on a private repo the same cadence would cost ~4,320
billed minutes/month of polling alone.)

### 2. Generate the keypair

On your own machine (never in this repo, never in chat):

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out runner-private.pem
openssl pkey -in runner-private.pem -pubout -outform DER | base64 -w0
```

The second command prints the **public** key (one long base64 line).
Put that value in the app as the runner public-key constant (it
replaces the TEST key currently embedded there — send it to Milo,
who embeds it and rebuilds; until then the app refuses verified
runs). Keep `runner-private.pem` on your machine only, and DELETE
it after pasting its contents as the `RUNNER_PRIVATE_KEY` secret
in §3 (this directory carries a `.gitignore` guarding `*.pem`, so
an accidental `git add` cannot sweep it in — but delete it anyway).

### 3. Add the three secrets

In the repo: Settings → Secrets and variables → Actions → New
repository secret, one each:

| Secret | Value |
|---|---|
| `SUPABASE_URL` | The database's REST URL, e.g. `https://<ref>.supabase.co` |
| `SUPABASE_SERVICE_KEY` | The database's service key (bypasses row security by design — the runner enforces the run invariants in code; see `runner.mjs`) |
| `RUNNER_PRIVATE_KEY` | The full contents of `runner-private.pem` (PKCS8 PEM, including the `-----BEGIN PRIVATE KEY-----` lines) |

### 4. Enable Actions

Actions → the `verified-runs` workflow → Enable. It runs every 10
minutes and can also be started by hand (Run workflow).

## Files

| File | What it is |
|---|---|
| `.github/workflows/verified-runs.yml` | Schedule (`*/10 * * * *` UTC) + manual `workflow_dispatch`. No `repository_dispatch` (needs a token; the schedule needs none). |
| `runner.mjs` | The runner (Node ≥ 20, no dependencies — built-ins only: `crypto`, `fetch`). Same tiers, finding contract, and no-evidence-no-finding rule as the browser runner. |
| `package.json` | No dependencies; scripts only (`npm start`, `npm run check`). |

## Logs

The runner logs run/request ids and counts **only** — never keys,
never project details, never findings. A normal run logs: claimed
request, key count, stored finding count, verified run id.

## Local check (no secrets, no network)

```sh
npm run check   # node --check runner.mjs
```

With secrets set, one manual run processes a single queued request:

```sh
SUPABASE_URL=... SUPABASE_SERVICE_KEY=... RUNNER_PRIVATE_KEY="$(cat runner-private.pem)" npm start
```

Without a queued request it exits 0 having done nothing. Without the
secrets it exits 1 without touching any row.
