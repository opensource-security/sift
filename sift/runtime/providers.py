"""
Provider and completion utilities for the live analysis path.

This module holds the raw provider call implementations (Anthropic, Ollama)
and the run_text_prompt dispatcher. It is intentionally free of replay-harness
or watchlist-specific logic so it can be consumed by both the live inline path
and the evaluation harness without cross-contamination.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable


ANTHROPIC_DEFAULT_MODEL = "claude-opus-4-6"
ANTHROPIC_DEFAULT_THINKING = "adaptive"
ANTHROPIC_DEFAULT_EFFORT = "max"


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ollama_complete(
    prompt: str,
    *,
    model: str,
    ssh_target: str,
    timeout_sec: int,
    temperature: int = 0,
) -> dict[str, Any]:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "seed": 0,
        },
    }

    base_cmd: list[str]
    if ssh_target.strip():
        base_cmd = [
            *shlex.split(ssh_target),
            "curl",
            "-sS",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "http://127.0.0.1:11434/api/generate",
            "-d",
            "@-",
        ]
    else:
        base_cmd = [
            "curl",
            "-sS",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "http://127.0.0.1:11434/api/generate",
            "-d",
            "@-",
        ]

    try:
        proc = subprocess.run(
            base_cmd,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        return {
            "ok": False,
            "error": f"Ollama timed out after {timeout_sec} seconds.",
            "raw_response": (stdout or "") + ("\n" + stderr if stderr else ""),
        }

    raw_response = proc.stdout.strip()
    stderr = proc.stderr.strip()
    if proc.returncode != 0:
        detail = stderr or raw_response or f"ollama exited with code {proc.returncode}"
        return {
            "ok": False,
            "error": f"Ollama runner failed: {detail}",
            "raw_response": raw_response + ("\n" + stderr if stderr else ""),
        }

    try:
        response_payload = json.loads(raw_response)
    except json.JSONDecodeError:
        return {
            "ok": False,
            "error": "Ollama API returned non-JSON output.",
            "raw_response": raw_response + ("\n" + stderr if stderr else ""),
        }

    response_text = (response_payload.get("response") or "").strip()
    return {
        "ok": True,
        "text": response_text,
        "raw_response": response_text,
    }


def anthropic_complete(
    prompt: str,
    *,
    model: str,
    api_key: str,
    timeout_sec: int,
    thinking_mode: str,
    effort: str,
    max_tokens: int = 1024,
    tools: list[dict[str, Any]] | None = None,
    tool_runner: Callable[[str, dict[str, Any]], Any] | None = None,
    max_tool_rounds: int = 0,
    max_total_tokens: int = 500000,
    cached_prefix: str = "",
) -> dict[str, Any]:
    temperature = 1 if thinking_mode == "adaptive" else 0
    if cached_prefix:
        user_content: list[dict[str, Any]] = [
            {"type": "text", "text": cached_prefix, "cache_control": {"type": "ephemeral"}},
            {"type": "text", "text": prompt},
        ]
    else:
        user_content = [{"type": "text", "text": prompt}]
    messages: list[dict[str, Any]] = [
        {"role": "user", "content": user_content}
    ]
    total_usage = {"input_tokens": 0, "output_tokens": 0}
    tool_trace: list[dict[str, Any]] = []
    response_transcript: list[dict[str, Any]] = []
    last_content_blocks: list[dict[str, Any]] = []

    def request_once(request_payload: dict[str, Any]) -> dict[str, Any]:
        request_body = json.dumps(request_payload).encode("utf-8")
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=request_body,
            headers={
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "anthropic-beta": "prompt-caching-2024-07-31",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            return json.loads(resp.read().decode("utf-8"))

    tool_round = 0
    while True:
        tool_round += 1
        if not tools and tool_round > 1:
            break
        if tools and max_tool_rounds > 0 and tool_round > max_tool_rounds:
            return {
                "ok": False,
                "error": f"Anthropic tool loop exceeded {max_tool_rounds} rounds.",
                "raw_response": json.dumps(response_transcript, ensure_ascii=False),
                "raw_content_blocks": last_content_blocks,
                "raw_response_payloads": response_transcript,
                "usage": {
                    "input_tokens": total_usage["input_tokens"] or None,
                    "output_tokens": total_usage["output_tokens"] or None,
                },
                "tool_trace": tool_trace,
            }
        request_payload: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
        }
        if effort and "haiku" not in model:
            request_payload["output_config"] = {"effort": effort}
        if thinking_mode == "adaptive" and "haiku" not in model:
            request_payload["thinking"] = {"type": "adaptive"}
        if tools:
            request_payload["tools"] = tools
            request_payload["tool_choice"] = {
                "type": "auto",
                "disable_parallel_tool_use": False,
            }

        _retry_attempt = 0
        _max_retries = 5
        while True:
            try:
                response_payload = request_once(request_payload)
                break
            except urllib.error.HTTPError as exc:
                error_body = ""
                try:
                    error_body = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
                if exc.code in (429, 529) and _retry_attempt < _max_retries:
                    retry_after = int(exc.headers.get("retry-after", 0) or 0)
                    wait = retry_after if retry_after > 0 else min(4 ** _retry_attempt, 60)
                    time.sleep(wait)
                    _retry_attempt += 1
                    continue
                return {
                    "ok": False,
                    "error": f"Anthropic API HTTP {exc.code}: {error_body[:500]}",
                    "raw_response": error_body,
                    "raw_content_blocks": last_content_blocks,
                    "raw_response_payloads": response_transcript,
                    "usage": {
                        "input_tokens": total_usage["input_tokens"] or None,
                        "output_tokens": total_usage["output_tokens"] or None,
                    },
                    "tool_trace": tool_trace,
                }
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                return {
                    "ok": False,
                    "error": f"Anthropic API request failed: {exc}",
                    "raw_response": "",
                    "raw_content_blocks": last_content_blocks,
                    "raw_response_payloads": response_transcript,
                    "usage": {
                        "input_tokens": total_usage["input_tokens"] or None,
                        "output_tokens": total_usage["output_tokens"] or None,
                    },
                    "tool_trace": tool_trace,
                }

        response_transcript.append(response_payload)
        usage = response_payload.get("usage", {}) or {}
        total_usage["input_tokens"] += usage.get("input_tokens") or 0
        total_usage["output_tokens"] += usage.get("output_tokens") or 0
        total_tokens_used = total_usage["input_tokens"] + total_usage["output_tokens"]

        content_blocks = response_payload.get("content", []) or []
        last_content_blocks = content_blocks
        messages.append({"role": "assistant", "content": content_blocks})
        tool_uses = [block for block in content_blocks if block.get("type") == "tool_use"]

        if not tool_uses:
            response_text = "".join(
                block.get("text", "") for block in content_blocks if block.get("type") == "text"
            ).strip()
            return {
                "ok": True,
                "text": response_text,
                "raw_response": json.dumps(response_transcript, ensure_ascii=False),
                "raw_content_blocks": content_blocks,
                "raw_response_payloads": response_transcript,
                "usage": {
                    "input_tokens": total_usage["input_tokens"],
                    "output_tokens": total_usage["output_tokens"],
                },
                "tool_trace": tool_trace,
            }

        if max_total_tokens > 0 and total_tokens_used >= max_total_tokens:
            return {
                "ok": False,
                "error": f"Anthropic tool loop exceeded token budget of {max_total_tokens} total tokens.",
                "raw_response": json.dumps(response_transcript, ensure_ascii=False),
                "raw_content_blocks": last_content_blocks,
                "raw_response_payloads": response_transcript,
                "usage": {
                    "input_tokens": total_usage["input_tokens"] or None,
                    "output_tokens": total_usage["output_tokens"] or None,
                },
                "tool_trace": tool_trace,
            }

        if not tools or tool_runner is None:
            return {
                "ok": False,
                "error": "Anthropic requested tool_use but no tool runner was configured.",
                "raw_response": json.dumps(response_transcript, ensure_ascii=False),
                "raw_content_blocks": last_content_blocks,
                "raw_response_payloads": response_transcript,
                "usage": {
                    "input_tokens": total_usage["input_tokens"] or None,
                    "output_tokens": total_usage["output_tokens"] or None,
                },
                "tool_trace": tool_trace,
            }

        tool_result_blocks: list[dict[str, Any]] = []
        for block in tool_uses:
            tool_name = str(block.get("name") or "").strip()
            tool_use_id = str(block.get("id") or "").strip()
            tool_input = block.get("input") or {}
            try:
                tool_output = tool_runner(tool_name, tool_input)
            except Exception as exc:
                tool_output = {"tool_name": tool_name, "ok": False, "error": str(exc)}
            tool_trace.append(
                {
                    "tool_round": tool_round + 1,
                    "tool_use_id": tool_use_id,
                    "tool_name": tool_name,
                    "input": tool_input,
                    "output": tool_output,
                }
            )
            tool_result_blocks.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": json.dumps(tool_output, ensure_ascii=False),
                }
            )
        messages.append({"role": "user", "content": tool_result_blocks})
    return {
        "ok": False,
        "error": "Anthropic tool loop ended unexpectedly.",
        "raw_response": json.dumps(response_transcript, ensure_ascii=False),
        "raw_content_blocks": last_content_blocks,
        "raw_response_payloads": response_transcript,
        "usage": {
            "input_tokens": total_usage["input_tokens"] or None,
            "output_tokens": total_usage["output_tokens"] or None,
        },
        "tool_trace": tool_trace,
    }


def run_text_prompt(
    prompt: str,
    runner_name: str,
    *,
    ollama_model: str,
    ollama_ssh_target: str,
    ollama_timeout_sec: int,
    anthropic_model: str = "",
    anthropic_api_key: str = "",
    anthropic_timeout_sec: int = 120,
    anthropic_thinking: str = ANTHROPIC_DEFAULT_THINKING,
    anthropic_effort: str = ANTHROPIC_DEFAULT_EFFORT,
    max_tokens: int = 1024,
    anthropic_tools: list[dict[str, Any]] | None = None,
    anthropic_tool_runner: Callable[[str, dict[str, Any]], Any] | None = None,
    anthropic_max_tool_rounds: int = 0,
    anthropic_max_total_tokens: int = 500000,
    cached_prefix: str = "",
) -> dict[str, Any]:
    if runner_name == "ollama":
        return ollama_complete(
            prompt,
            model=ollama_model,
            ssh_target=ollama_ssh_target,
            timeout_sec=ollama_timeout_sec,
            temperature=0,
        )
    if runner_name == "anthropic":
        return anthropic_complete(
            prompt,
            model=anthropic_model,
            api_key=anthropic_api_key,
            timeout_sec=anthropic_timeout_sec,
            thinking_mode=anthropic_thinking,
            effort=anthropic_effort,
            max_tokens=max_tokens,
            tools=anthropic_tools,
            tool_runner=anthropic_tool_runner,
            max_tool_rounds=anthropic_max_tool_rounds,
            max_total_tokens=anthropic_max_total_tokens,
            cached_prefix=cached_prefix,
        )
    return {
        "ok": False,
        "error": f"runner {runner_name} does not support raw text prompts",
        "raw_response": "",
    }
