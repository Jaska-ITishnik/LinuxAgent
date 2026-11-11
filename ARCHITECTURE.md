# Repository audit and architecture preparation

## Scope and current state

This document records the repository as it exists before modular migration. The current runnable entry point is `agents.py`. `TODO` describes a target exercise with six capabilities, but those six tools are not implemented in the current script. The registered tools today are system status, listing recent regular files directly in `~/Downloads`, finding large files directly in `~/Downloads`, and launching one of three allowlisted desktop applications after approval.

The CLI uses Rich prompts and panels, keeps conversation history in memory, and connects to a local Ollama server. `AGENT_MODEL` and `OLLAMA_HOST` are read from the environment; defaults are `gemma4:e2b-it-qat` and `http://127.0.0.1:11434`. Other runtime limits are constants in `agents.py`. The local `.env` is ignored by git and is not loaded explicitly by the script. There is no dependency manifest or test suite in the repository at audit time. The ignored `.venv` currently contains `ollama`, `rich`, and `psutil`.

## Existing execution flow

1. `main()` renders the banner and calls `check_server()` to verify Ollama connectivity and model availability.
2. The Rich prompt reads user input and handles `/help`, `/tools`, `/clear`, and exit commands.
3. `process()` combines the system prompt, recent in-memory history, and the current user message, then asks Ollama to select from the registered tools.
4. Each returned tool call passes through `call_tool()`, which checks the tool name, argument object, and allowed argument keys. `open_application` additionally restricts the app name and asks the user for approval.
5. Python functions perform the selected local operation. Results are serialized into tool messages and passed back to the model for a streamed response.
6. The user/assistant exchange is retained in memory for the next prompt.

## Audit findings

### Architecture and coupling

- `agents.py` combines CLI presentation, configuration, Ollama connectivity, model orchestration, tool registration, validation, authorization prompting, system inspection, filesystem inspection, and process launching.
- Tool call validation is a single dispatcher with tool-specific conditions, rather than a common typed interface with per-tool schemas and policies.
- The Ollama `Client`, Rich `Console`, and prompt operations are module globals, which makes isolated testing and alternate interfaces difficult.
- Tool results are dictionaries and are formatted/serialized in orchestration code; there is no shared result contract.
- Conversation history is ephemeral and has no storage abstraction.
- Tool execution and presentation are intertwined, including the consent prompt in `call_tool()`.

### Security and reliability

- The code does not execute model-generated shell commands or Python code. The app launcher uses a fixed argument list and `shell=False`, with an allowlist and explicit approval.
- Model-generated tool arguments are untrusted. `call_tool()` rejects unknown tools, non-dictionary arguments, unexpected keys, and unsupported app names; preserve these checks when moving code.
- `MAX_TOOL_ROUNDS` limits planning loop iterations, but a single model response may contain multiple calls and the current implementation executes all of them without a separate per-task call-count cap. The current path returns after processing that tool batch, so it does not currently perform repeated plan/execute rounds.
- The subprocess launch is appropriately allowlisted but `Popen` failures are converted to an error result. The caller should continue to report “launch requested” rather than asserting that a window opened.
- Tool output is inserted into model context. The system prompt warns that output is untrusted, but this is guidance to the model and not a technical isolation boundary.
- Downloads scanning is non-recursive, skips symlinks, and catches some filesystem races. It is fixed to the current user’s Downloads directory rather than accepting an LLM-selected path.
- Broad exception handling at the CLI boundary displays exception text to the user; review whether remote error details should be reduced in a later implementation phase.
- There is no explicit dependency lock/manifest, so a clean install is not currently reproducible from tracked files.

### Functionality and validation gaps

- `TODO` describes file search by name/extension, text reading, confirmed note writing, arithmetic, system status, and weather. The runnable script currently implements only system status among those six, alongside file listing, large-file discovery, and app launching.
- No tests are present. The `tests/` package is a preparation point, not evidence of test coverage.

## Proposed module responsibilities

The following layout is a migration target. The current script remains the operational entry point during this preparation task.

```text
agents.py                 Existing CLI entry point, preserved during migration
core/                     Configuration, agent orchestration, typed shared contracts
  __init__.py
tools/                    Individual tool implementations and registry
  __init__.py
security/                 Argument validation, authorization policies, limits
  __init__.py
interfaces/               CLI presentation and interface adapters
  __init__.py
storage/                  Persistence interfaces and SQLite implementations
  __init__.py
tests/                    Unit and integration tests for modules and flows
  __init__.py
ARCHITECTURE.md            Audit findings and migration guidance
```

- `core/`: own application configuration, model-independent agent flow, tool/result interfaces, and orchestration contracts. Keep Ollama-specific request details behind an adapter in this layer or a dedicated provider module when the project grows.
- `tools/`: implement each capability behind a narrow typed interface; avoid importing CLI presentation code. A registry exposes declared tool schemas and dispatches validated requests.
- `security/`: centralize schema validation, tool authorization, consent policy, and execution budgets. Default-deny unknown tool names and arguments. Keep policy decisions independent of model output.
- `interfaces/`: own Typer/Rich command handling and display. It should call application interfaces, not implement tools or security policy.
- `storage/`: own SQLite connection lifecycle, schema/migrations, and persistence repositories. Core depends on repository interfaces, not SQLite details.
- `tests/`: cover validators and policies, individual tools with injected dependencies, orchestration with a fake model client, and CLI behavior without requiring a live Ollama server.

## Dependency direction

```text
interfaces  ──>  core contracts / application service  ──>  tools interfaces
                         │                       │
                         ├──> security policies  └──> storage interfaces
                         └──> model provider adapter

tools, model provider, and SQLite repository implementations depend inward on
core contracts where needed. Core must not depend on Rich, concrete SQLite
connections, or tool-specific implementation details. Tests can depend on all
layers and inject fakes at boundaries.
```

External effects (Ollama HTTP, filesystem, process launch, system metrics, SQLite) should enter through narrow interfaces or injected collaborators. Model output proposes a tool call; security validates and authorizes it; only then may a tool implementation execute.

## Tool execution lifecycle

1. The interface passes user input to the application service.
2. Core builds model context from trusted instructions, conversation state, and clearly marked untrusted user/tool data.
3. The model provider returns a proposed tool name and arguments. This proposal is data, never executable code or policy.
4. Security validates the name, exact argument schema, types, bounds, authorization, consent requirement, and remaining per-task time/call budget. Invalid proposals do not reach a tool.
5. The tool executes through constrained dependencies. Destructive or externally visible actions require explicit user confirmation before execution.
6. The result is normalized to a bounded, typed representation and marked as untrusted when returned to the model.
7. Core enforces the task-wide step budget and either asks the model for the next decision or returns a final response.
8. The interface renders progress and errors. Storage persists only data the application explicitly chooses to retain.

## Migration strategy

1. Keep `agents.py` as the compatibility entry point. Add package boundaries without changing behavior, then add characterization tests around current tool outputs, dispatcher validation, and CLI commands.
2. Move configuration and shared types into `core/`; inject the Ollama client and console/prompt dependencies. Keep defaults and environment variable names stable.
3. Move each existing tool into `tools/`, preserving current limits and result shapes while routing every invocation through centralized `security/` validation and authorization.
4. Move Rich interaction into `interfaces/` and keep agent orchestration independent of terminal I/O. Preserve a direct `python agents.py` launch path throughout.
5. Introduce storage interfaces and SQLite behind `storage/` only when persistence requirements are implemented; do not make the current in-memory conversation behavior depend on SQLite prematurely.
6. Add and migrate the six `TODO` capabilities as separate scoped work, each with unit tests and explicit safety policies. Do not infer that they already exist from the exercise notes.
7. At each step, run unit tests and a CLI smoke test with a fake Ollama client; use a live local Ollama/model check only as an environment-dependent integration check.

The Task 01 preparation added package placeholders and this migration document without relocating the original CLI implementation.

## Dispatcher execution limits

The `core.tool_dispatcher` component dispatches only enabled definitions obtained from `ToolRegistry`, validates arguments before authorization, and denies requests when no authorizer is configured. Synchronous implementations run in a bounded worker pool. A timeout stops waiting and cancels work that has not started, but Python cannot forcibly terminate a synchronous function that is already running. Such a function may continue until it returns; the fixed worker limit bounds concurrent background work, and occupied worker slots are retained until those calls actually finish. Async implementations are cancelled on timeout and must cooperate with cancellation. Tools that perform blocking or non-cancellable work should use their own operation deadlines or a separately supervised process boundary.

## Security foundation and execution flow (Tasks 06–09)

- `security.path_guard.PathGuard` requires explicit, existing, non-root allowed directories. It rejects traversal, protected locations, sensitive path names, and symlink components. File creation and reading use descriptor-relative `openat`-style operations with `O_NOFOLLOW`; new files are created exclusively with owner-only permissions. Directory enumeration and metadata use no-follow entries and bounded scans. `security.allow_protected_paths` is an explicit opt-in and does not expand the configured allowed roots.
- `security.permissions.PermissionPolicyEngine` maps registry permission levels to allow, approval, or deny. `security.approval.ApprovalManager` asks a trusted interface, binds the answer to the validated tool and exact arguments, expires it, and consumes it once. The Rich CLI is the approval source; model text is never treated as consent. Current policy is rechecked immediately before dispatch.
- `security.audit_logger.AuditLogger` writes JSONL events beneath the XDG data directory (`~/.local/share/linuxagent/logs/audit.log`), uses owner-only file/directory permissions, redacts secret fields and document contents, rotates by configured size/day, and prunes rotated logs according to `logging.retention`.
- `core.agent_controller.AgentController` owns the bounded model/tool loop. It enforces configured step, tool-call, retry, and wall-clock limits; passes every tool proposal to `ToolDispatcher`; returns normalized tool results to the model; and supports asyncio cancellation and progress callbacks. Read-only failures may be retried; operations that can change state are not retried automatically.
- `core.runtime.create_agent_runtime` composes configuration, path guard, registry, approval policy, audit logger, dispatcher, Ollama adapter, and controller. `agents.py` uses this runtime as the CLI execution path.

## Registered tool set (Tasks 10–11)

`tools.functional` registers `search_files`, `read_text_file`, `create_note`, `calculate`, `get_system_status`, and `get_weather`. `tools.advanced_files` registers `list_directory`, `search_files_advanced`, `get_file_metadata`, and `find_large_files`, and preserves `list_downloads` as a recent-file compatibility listing. Filesystem tools use the configured `PathGuard`; recursive scans stop at depth 10 and 10,000 inspected entries, and all results are paginated or size-bounded. Notes require approval and are never overwritten. The arithmetic tool parses a restricted Python AST and does not evaluate arbitrary code. Weather uses fixed Open-Meteo endpoints with request timeouts. The original fixed-allowlist desktop launcher remains registered as a controlled, approval-gated compatibility tool.

The CLI defaults to the explicit `~/Downloads` root and users can override `security.allowed_roots` in `config.yaml`. To permit a protected location, configure both the allowed root and `security.allow_protected_paths: true`; this should be done only when the user explicitly intends the broader access.

The unit/integration suite uses temporary directories, fake approval interfaces, fake Ollama responses, and a mocked weather transport. A live Ollama/model and external weather request are environment-dependent checks and are not part of the default test run.

## Controlled files, archives, and system monitoring (Tasks 12–14)

`tools.controlled_files` registers approval-gated copy, move, rename, and directory creation without overwrites. `tools.archives` provides read-only organization previews and SHA-256 duplicate discovery, plus approval-gated ZIP/TAR creation and bounded extraction into a new directory. Archive members must be regular files with safe relative paths; extraction enforces file, size, and compression-ratio limits. `tools.system_monitor` exposes CPU/core, RAM/swap, mounted-filesystem, and bounded process summaries; process command lines and environment variables are never collected, and inaccessible mounts/processes are counted rather than exposing error details.

`tools.network_diagnostics` reports interface status and traffic counters without exposing IP addresses, checks connectivity only against the two registered trusted HTTPS endpoints (with redirects and proxy environment settings disabled), inspects one PID without command lines or environment variables, and reports system uptime. It performs no scanning or process control.

`tools.web` implements bounded public webpage fetch/extractive summaries, exchange-rate lookups through two fixed providers, and website status checks. It permits HTTPS on port 443 only, resolves every initial/redirect hostname, rejects any non-global answer, pins the TCP connection to one of the validated numeric addresses while preserving TLS hostname verification, disables proxy environment settings, and manually validates at most three redirects. Page text is explicitly marked untrusted; query values that resemble credentials are redacted from returned source URLs.

`tools.documents` reads PDF, DOCX, CSV, and XLSX only through `PathGuard`; each input is capped at 20 MiB, zip-based formats are checked for entry count, expansion size, and compression ratio, and all extracted content/rows are bounded. DOCX/XLSX parsing does not fetch external resources, macros are not supported, and XLSX uses cached values rather than evaluating formulas. Extracted document content is marked untrusted.

`tools.document_writers` creates Markdown, DOCX, CSV, and XLSX documents using temporary same-directory files and descriptor-relative, atomic no-overwrite publication. Each published file is reopened and verified. Spreadsheet text is forced to string cells or escaped for CSV, and the registry policy always requires trusted approval for these four writers even if the global policy otherwise allows controlled writes.

`tools.developer` provides bounded project-tree/dependency inspection, literal source search with secret redaction, and Git status/diff. It executes no project code and invokes only fixed Git subcommands with shell disabled, time/output limits, hooks/pagers/external diff/textconv disabled, and repository includes/custom filters rejected. The `developer` tool category is enabled by default but can be disabled through the existing category setting.

## Persistent memory (Task 20)

`storage.database.SQLiteDatabase` stores a versioned schema in the XDG application data directory with owner-only database permissions, no-follow file creation, private directory checks, transactional migrations, and SQLite trusted-schema restrictions. `core.memory.MemoryService` stores redacted conversations, task history, bounded tool summaries, and explicitly approved notes; persistent preferences require the same explicit consent flag. The runtime persists tasks automatically to this local store, while note persistence is only available through the consent-gated service API. History and notes expire after the configured service retention window (90 days by default); users can delete one note, a task, a session, or all memory with explicit confirmation. Common credential patterns are redacted before storage; this is a defense-in-depth filter, not a guarantee against every possible secret format.
