# Detection automation queue

This package collects threat reports into a dedicated SQLite queue and invokes the compiled [`agents/`](../agents/) CLI. It replaces the legacy placeholder that marked empty work completed.

The supported default is **disabled**. Dry runs exercise the adapter and queue using synthetic agent output. Live mode is experimental and can run Attack Range tests, query Splunk, and write detection/data artifacts. A live result requires evidence and human review; this queue never publishes or merges PRs.

## Install and verify

Use Node 22.13+ for the whole repository (the standalone queue supports Node 20+). From the repository root:

```sh
npm ci
npm run build
npm ci --prefix agents
npm run build --prefix agents
npm ci --prefix automation
npm test --prefix automation
npm run test:agents --prefix automation
```

The last command uses the actual compiled agents CLI with synthetic input, a disposable database, and no live credentials. It must end with a `simulated` job and zero approval requests.

## Explicit setup

Use a new database in an existing private directory. Do not share the MCP cache: reindexing replaces that cache.

```sh
export AUTOMATION_DB_PATH=/absolute/private/path/automation.sqlite
export AUTOMATION_MODE=dry-run
npm run migrate --prefix automation
npm run loop --prefix automation
```

`loop` processes at most one pending job; an empty queue is a no-op. `npm start --prefix automation` polls continuously. Ctrl+C/SIGTERM stops after the current invocation, whose default timeout is 30 minutes. The foreground launcher does not create PID files or background daemons.

`AGENTS_CLI_PATH` optionally overrides the sibling `agents/dist/src/cli.js` path. All adapter input travels through a private temporary file and `execFile` arguments, never a shell command. Temporary input is deleted after the child exits.

## Collection and scheduling

`npm run collect --prefix automation` explicitly fetches CISA advisories and KEV, regardless of worker mode. It writes feed records and one queued analysis per new source-qualified feed ID. Collection failures exit nonzero; successfully ingested items remain, and retries deduplicate them. Network requests have a 30-second timeout and 8 MiB response limit.

Schedules are opt-in and stored in SQLite, with UTC expressions:

```sh
npm run scheduler --prefix automation -- add cisa-hourly '0 * * * *'
npm run scheduler --prefix automation -- status
npm run scheduler --prefix automation -- start
```

The scheduler only queues `feed_collection`. A worker executes those scheduled collections only with `AUTOMATION_MODE=live`; disabled/dry-run workers block those jobs. Unsupported schedule types fail explicitly. Feed definitions live in `collectors/multi-source-collector.ts`; `config/autonomous.yml` is an annotated reference, not loaded configuration.

## Results and human review

| Job state | Meaning |
| --- | --- |
| `pending` / `running` | Queued / claimed by one worker |
| `simulated` | Synthetic dry-run output; no validation or coverage claim |
| `awaiting_approval` | Live result passed adapter checks and has persistent artifacts |
| `reviewed` | A local reviewer accepted the stored result; nothing was published |
| `cancelled` | Review rejected or expired |
| `blocked` | Configuration, unsupported operation, or incomplete evidence needs intervention |
| `failed` | Transient failures exhausted the configured attempts |
| `completed` | Successful feed collection only, never threat analysis |

```sh
npm run approvals --prefix automation -- list
npm run approvals --prefix automation -- approve approval_ID
npm run approvals --prefix automation -- reject approval_ID 'reason'
npm run approvals --prefix automation -- check-expired
npm run report --prefix automation -- weekly /absolute/path/report.md
```

Approval records the local OS username; it is a local operator tool, not an authenticated multi-user service. It never replays the pipeline. Navigator reports include only reviewed live detections and make no deployment or measured-coverage claims.

See [deployment and recovery](DEPLOYMENT.md), [behavior and architecture](ARCHITECTURE.md), and [tests](TESTING-GUIDE.md) before considering live mode.
