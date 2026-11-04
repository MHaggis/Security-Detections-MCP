# Deployment and recovery

The tested integration is local SQLite plus the compiled agents CLI in dry-run mode. Live infrastructure execution has not been certified by these tests. Do not install a continuous live worker until you have reviewed the agents package configuration and exercised one controlled job in your own isolated range.

## Live prerequisites

Build the root, agents, and automation packages as described in the README. Choose a dedicated `AUTOMATION_DB_PATH` outside the MCP cache and restrict filesystem access: the queue stores feed content, pipeline results, and local review history.

Live operation requires explicit `AUTOMATION_MODE=live`, `ANTHROPIC_API_KEY`, and existing absolute `SECURITY_CONTENT_PATH`, `ATTACK_DATA_PATH`, and `ATTACK_RANGE_PATH` directories. Configure the agents package's MCP/LLM/Splunk connections separately. The adapter refuses mock fallback and incomplete returned evidence. This is not a substitute for inspecting generated code and running only authorized range tests.

Keep artifacts in persistent repositories. The temporary subprocess working directory is deleted after invocation. Start with `npm run loop --prefix automation`, inspect the result and artifacts, then decide whether to run the foreground worker under your own process supervisor. Do not overlap jobs against the same mutable range/content checkout without independent isolation.

## Stop and recover

SIGINT/SIGTERM asks the worker to finish its current bounded invocation and close SQLite. The direct child has a 30-minute timeout. A forced process kill may leave a job `running` and external descendants or side effects alive; subprocess timeout is not a remote rollback or process-tree cleanup guarantee.

Before retrying a `running`, `blocked`, or `failed` job:

1. Stop all workers using that database and verify any old range/subprocess work is stopped.
2. Back up SQLite consistently (SQLite backup API or CLI `.backup`), including the independent artifact repositories.
3. Inspect the job's error/result, artifact paths, and external range state. Resolve the cause and decide whether replay is safe. A partial live invocation may already have written files or executed tests.
4. Only then, in one SQLite transaction, reset that specific job to `pending`, clear `error`/`result`, set `retry_count=0`, clear `started_at`/`completed_at`, and update the linked feed state to `pending`. Never reset a reviewed result to rerun publication.

Failed or unreadable live invocations and failed persistence of live results become `blocked`; they are never automatically retried. There is intentionally no automatic lease expiry/replay. Review expiry is also explicit (`approvals -- check-expired`) and cancels the job; it never grants approval on timeout.

## Existing installations

Use a fresh dedicated database for installations that used the old placeholder. Old `completed` results are not trustworthy evidence of detection work. Retain the old database for audit; do not automatically reinterpret or enqueue its records. An incompatible legacy approval table is rejected with instructions to choose a new database.

No service, cron entry, remote infrastructure, or notification channel is enabled by installation. Backups, rotation, and retention are operator-managed. The checked-in YAML is documentation only.
