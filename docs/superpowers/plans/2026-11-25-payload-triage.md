# Payload Triage (OpenRouter Decisions) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Opt-in MCP tool `payload_triage(site_id)` that sends files flagged by `payload_scan` rules to an OpenRouter Decisions model and returns verdicts.

**Architecture:** Optional `triage` block in existing `config.json`; absent → tool not registered, server stays zero-network. New `triage.py` reuses `Audit.collect` + the payload rules, redacts secrets, one `POST /api/alpha/decisions` per file via stdlib `urllib`. API key read per call from an admin-owned file with `read_abs` (no-follow, bounded).

**Tech Stack:** Python >=3.11 stdlib, `mcp>=1.12,<2` FastMCP, `unittest`.

**Spec:** conversation 2026-11-25 (option B: config). Decisions below are the spec.

## Global Constraints

- Config shape: `"triage": {"model": str, "api_key_file": abs path, "max_items"?: int, "max_file_bytes"?: int, "timeout_seconds"?: int}`; unknown keys rejected.
- `max_items`: default 50; int >= 1; **values > 1000 are clamped to 1000** (not rejected). bool rejected.
- `max_file_bytes`: default 262144, clamp to `MAX_FILE` (2 MiB). `timeout_seconds`: default 30, clamp 1..120.
- `model` matches `[a-z0-9~][a-z0-9.\-/:]{0,99}`.
- Tool argument is only `site_id`. No path, key, model, or limit from client.
- API key never returned, never in `errors`, never logged.
- One file = one request to `https://openrouter.ai/api/alpha/decisions`; body `{model, state, questions, provider: {data_collection: "deny", zdr: true}}`.
- Answer `type` other than expected (refusal/missing) → item `verdict: "unanswered"`, never `benign`.
- Tests never touch network (stub `post`).

## Review Focus

- `max_items` 5000 in config → effective 1000, reported as `max_items: 1000` in result.
- Key file is symlink / missing / empty → `errors: ['api_key_unavailable']`, no request sent, no key text in result.
- HTTP error body echoing request (may contain file text) → only `http_<code>` error code stored, body discarded.
- Provider returns `{"type":"refusal"}` → `unanswered`.
- More flagged files than `max_items` → `truncated: true`.

---

### Task 1: Config schema

**Files:**
- Modify: `src/mcp_audit_security/core.py` (`load_config`, add `RULES`, `MAX_TRIAGE_ITEMS = 1000`)
- Modify: `config.example.json`
- Test: `tests/test_audit.py`

**Interfaces:**
- Produces: `core.RULES: dict[str, re.Pattern]` (moved from `payload_scan`, same 4 rules); `load_config` returns `config['triage']` normalized with all 5 keys filled and clamped.

- [x] Test `test_triage_config`: valid block → `max_items == 50`; `max_items: 10010` → `1000`; `max_items: 0`, `True`, `"5"`, relative `api_key_file`, unknown key `"x"` → `ConfigError`; no `triage` → key absent.
- [x] Run `python -m unittest tests.test_audit -v` → FAIL.
- [x] Implement: `set(config) <= {'sites','triage'}` and `'sites' in config`; validate/clamp triage; `payload_scan` uses `RULES`.
- [x] Run → PASS, existing tests still PASS.

### Task 2: Triage module

**Files:**
- Create: `src/mcp_audit_security/triage.py`
- Test: `tests/test_triage.py`

**Interfaces:**
- Consumes: `Audit.collect(roots, visitor)`, `RULES`, `read_abs`, config `triage`.
- Produces: `class Triage(audit, cfg)`, `.payload_triage(site_id) -> dict` with `{items:[{path, sha256, rules, verdict, confidence, p_webshell, risk}], errors, truncated, max_items, model}`; module `post(url, key, body, timeout) -> dict` (stubbed in tests); `redact(bytes) -> bytes`.

- [x] Test: stub `post` returning Decisions answer → item `verdict == 'webshell'`; refusal → `'unanswered'`; 3 flagged files with `max_items: 2` → 2 items, `truncated`; key value and file text absent from `json.dumps(result)`; `DB_PASSWORD` redacted in `state` captured by stub; key symlink → `api_key_unavailable`, stub never called.
- [x] Run → FAIL. Implement. Run → PASS.

### Task 3: Server wiring + docs

**Files:**
- Modify: `src/mcp_audit_security/server.py`, `README.md`
- Test: `tests/test_mcp.py`

- [x] Register `payload_triage` only when `'triage' in config`, annotations `openWorldHint: True`, `idempotentHint: False`.
- [x] README: new tool row, triage config section, egress note replacing "tidak ada request URL" absolutism.
- [x] Run full suite → PASS.
