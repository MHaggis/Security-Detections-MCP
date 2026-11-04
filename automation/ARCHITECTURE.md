# Automation behavior

```text
configured feeds -> parser -> atomic feed + job insert -> SQLite pending queue
                                                        |
                                                   atomic claim
                                                        |
                                            compiled agents CLI subprocess
                                                        |
                                simulated / blocked / failed / awaiting_approval
                                                                        |
                                                           local human review
                                                                        |
                                                               reviewed / cancelled
```

`FeedStore.ingest` uses an immediate transaction for deduplication, feed insertion, queue insertion, and the reverse job link. Queue selection honors lower numeric priority first. Workers claim with a compare-and-set transaction; a stale selection cannot execute a claimed job twice.

`createAgentsAdapter` launches Node with an argv array and a private temporary input file. The subprocess executes the existing LangGraph pipeline, not Cursor agent prompt files. A bounded timeout and output size prevent an unbounded direct child invocation. CLI output is parsed against its result marker and required structure. Missing techniques, malformed JSON, and structured errors fail instead of becoming an empty success.

Dry-run output is `simulated`. Live output must stop at `awaiting_approval`, contain no staged PRs, have no mock/skipped warnings, and include validated detections with passing QA, positive SIEM event counts, matching completed atomic tests, and persistent nonempty artifacts. An early no-gap return is blocked because the agents coverage path cannot currently prove a successful coverage query in every case.

The adapter is a boundary around an existing experimental pipeline; output checks do not independently establish the correctness of generated SPL, test effects, or export contents. A reviewer must inspect them. Persistent artifacts outside the temporary working directory survive cleanup. Structured results and review requests commit atomically with job/feed status.

Transient failures increment attempts and stop at `max_retries` (default three). Configuration/evidence failures become `blocked` without consuming retries. This implementation deliberately has no automatic abandoned-job replay: live jobs can have external side effects. See the recovery procedure before restarting a job after a crash.

Review transitions the persisted result to `reviewed` or `cancelled` and cannot queue another invocation. The agents CLI has no durable resume/checkpoint protocol, so approval does not stage PRs. A future publisher needs a separate reviewed contract and idempotent resume design.

The schema retains unused legacy campaign/validation tables for compatibility; this queue does not populate them. Notifications and learning prompt files are optional standalone scaffolding, not wired automation. No YAML settings, autonomous learning, retention, backups, or automatic deployments are implied by their presence.
