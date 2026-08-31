# Full Llama agentic-security evaluation

This branch runs the SINCONF validation matrix against a **real Meta Llama model** rather than the original lookup-table reasoning simulator.

## Model and scope

- Runtime: Ollama on GitHub-hosted Ubuntu runners.
- Model: `llama3.1:8b` (Meta Llama 3.1 8B), selected because it supports tool calling and fits the standard 16-GB GitHub runner.
- This is **not** presented as a Llama 3.3 70B result. A 70B replication requires a GPU/cloud endpoint with substantially more memory.
- Main corpus: 241 rows (164 attacks, 77 benign) across V1-V5.
- Additional tests: 50 adaptive cases (A1-A4), 39 legitimate privileged tasks, and 20 benign multi-step tasks.
- Modes: M0, M1, M2, M3lex, M3cap.
- Repeats: 5.
- Total evaluation cells: 8,750, split deterministically across 20 shards.

All external actions are synthetic stubs. The benchmark never sends real email, executes arbitrary code, writes databases, deletes files, or posts data externally.

`M3lex` reproduces the original lexical orchestration/egress behavior. `M3cap` is an oracle capability-bound upper comparator whose authorized tools come from scenario metadata; it is not claimed to be a deployable semantic authorization classifier.

For non-V1 attacks in the archived 241-row corpus, the archive lacks a paired legitimate user-task context, so indirect content is evaluated under a standardized external-document summarization task. This limitation must be disclosed in any manuscript based on these results.
