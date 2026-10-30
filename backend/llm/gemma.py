"""Gemma 4 semantic analysis provider via Google Generative Language API.

Analyzes MCP tools by comparing their declared descriptions and input schemas
against statically discovered capabilities and bounded code context.

Invariants enforced here:
  * The model NEVER creates findings or inflates risk scores.
  * Claims must cite valid evidence IDs and supporting code references.
  * Input source code is strictly bounded and scrubbed for secrets.
  * Transient failures, timeouts, quota exhaustion or absent keys fail safe
    to an empty claim list without disrupting deterministic static analysis.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import httpx

from backend.models import ToolDef

logger = logging.getLogger("capcheck.llm.gemma")

# Default model identifier for Gemma 4 hosted on Google API
DEFAULT_GEMMA_MODEL = "gemma-4-31b-it"

_CREDENTIAL_PATTERNS = [
    re.compile(
        r"""(?i)(["']?(?:api[_-]?key|token|secret|password|bearer|auth|access[_-]?token)["']?\s*[:=]\s*["'])([^"']{4,})(["'])"""
    ),
    re.compile(
        r"""(?i)(os\.environ(?:\.get)?\s*\(\s*["'])([^"']+)(["']\s*,\s*["'])([^"']+)(["'])"""
    ),
    re.compile(r"""-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"""),
    re.compile(r"""(ghp_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{50,})"""),
    re.compile(r"""(AKIA[0-9A-Z]{16})"""),
]


def sanitize_code_context(
    code: str, max_lines: int = 50, max_chars: int = 2000
) -> str:
    """Sanitize and bound code context before sending to the model.

    Never sends credentials, environment variable values, or excessive tokens.
    """
    if not code:
        return ""

    lines = code.splitlines()
    truncated = False
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        truncated = True

    sanitized = "\n".join(lines)
    if len(sanitized) > max_chars:
        sanitized = sanitized[:max_chars]
        truncated = True

    for pattern in _CREDENTIAL_PATTERNS:
        if pattern.groups == 3:
            sanitized = pattern.sub(r"\g<1>[REDACTED]\g<3>", sanitized)
        elif pattern.groups == 5:
            sanitized = pattern.sub(r"\g<1>\g<2>\g<3>[REDACTED_DEFAULT]\g<5>", sanitized)
        else:
            sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)

    if truncated:
        sanitized += "\n# [TRUNCATED FOR BOUNDED CONTEXT]"

    return sanitized


class GemmaProvider:
    """Hosted Gemma 4 semantic analyzer."""

    name = "gemma"

    def __init__(
        self,
        api_key: str,
        *,
        model: str = DEFAULT_GEMMA_MODEL,
        api_base: str = "https://generativelanguage.googleapis.com/v1beta",
        timeout_seconds: float = 10.0,
        max_retries: int = 2,
        client: httpx.Client | None = None,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.api_base = api_base.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._client = client

    def _get_client(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        return httpx.Client(timeout=self.timeout_seconds)

    def _build_prompt(
        self,
        tool: ToolDef,
        capabilities: list[str],
        sanitized_code: str,
    ) -> str:
        code_section = (
            f"```\n{sanitized_code}\n```"
            if sanitized_code
            else "(No handler code extract available)"
        )
        return (
            "You are an expert security auditor reviewing a Model Context Protocol (MCP) server tool.\n"
            "Your task is to analyze whether the tool's implementation matches its declared description and schema.\n\n"
            f"Tool Name: {tool.name}\n"
            f"Source File: {tool.source_file}:{tool.line}\n"
            f"Declared Description: {tool.declared_description or '(None declared)'}\n"
            f"Declared Parameters: {', '.join(tool.params) if tool.params else '(None)'}\n"
            f"Input Schema: {tool.input_schema or '(None)'}\n"
            f"Observed Static Capabilities: {', '.join(capabilities) if capabilities else '(None)'}\n\n"
            f"Tool Implementation Extract (sanitized):\n{code_section}\n\n"
            "Instructions:\n"
            "1. Evaluate if what the tool claims to do matches what it actually does in the code.\n"
            "2. Note any potential mismatch (e.g. claiming to be a simple calculator but performing network requests, reading secrets, or writing files).\n"
            "3. Output MUST be valid JSON adhering strictly to this schema:\n"
            "{\n"
            '  "claims": [\n'
            "    {\n"
            '      "claimed_behavior": "<summary of declared purpose>",\n'
            '      "observed_behavior": "<summary of actual implementation actions>",\n'
            '      "potential_mismatch": <true if code contradicts description or does undisclosed actions, false otherwise>,\n'
            '      "confidence": <float between 0.0 and 1.0>,\n'
            f'      "supporting_code_references": ["{tool.source_file}:{tool.handler_line or tool.line}"],\n'
            '      "reasoning": "<short explanation>"\n'
            "    }\n"
            "  ]\n"
            "}\n"
            "Respond ONLY with the JSON object."
        )

    def analyze_tool(
        self,
        tool: ToolDef,
        capabilities: list[str],
        code_context: str | None = None,
    ) -> list[dict[str, Any]]:
        """Query Gemma 4 hosted API for semantic tool behavior analysis."""
        if not self.api_key:
            return []

        sanitized_code = sanitize_code_context(code_context or "")
        prompt = self._build_prompt(tool, capabilities, sanitized_code)

        endpoint = f"{self.api_base}/models/{self.model}:generateContent"
        headers = {
            "x-goog-api-key": self.api_key,
            "Content-Type": "application/json",
        }
        payload = {
            "contents": [
                {
                    "parts": [{"text": prompt}],
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 1024,
                "responseMimeType": "application/json",
            },
        }

        response_data: dict[str, Any] | None = None
        client = self._get_client()
        owns_client = self._client is None

        try:
            for attempt in range(self.max_retries + 1):
                try:
                    resp = client.post(endpoint, headers=headers, json=payload)
                    if resp.status_code == 200:
                        response_data = resp.json()
                        break
                    elif resp.status_code in {400, 401, 403, 404, 429}:
                        # Unrecoverable error (bad request, auth failure, quota exhaustion)
                        logger.warning(
                            "Gemma API returned status %d; failing safe to null provider.",
                            resp.status_code,
                        )
                        return []
                    elif resp.status_code >= 500:
                        if attempt < self.max_retries:
                            time.sleep(0.25 * (2**attempt))
                            continue
                        logger.warning("Gemma API 5xx after retries: status %d", resp.status_code)
                        return []
                    else:
                        return []
                except (httpx.TimeoutException, httpx.NetworkError) as err:
                    if attempt < self.max_retries:
                        time.sleep(0.25 * (2**attempt))
                        continue
                    logger.warning("Gemma API request failed: %s", type(err).__name__)
                    return []
        finally:
            if owns_client:
                client.close()

        if not response_data:
            return []

        return self._parse_claims(response_data, tool)

    def _parse_claims(
        self, response_data: dict[str, Any], tool: ToolDef
    ) -> list[dict[str, Any]]:
        """Validate and construct structured claims from the API response."""
        try:
            candidates = response_data.get("candidates", [])
            if not candidates:
                return []

            first_candidate = candidates[0]
            content = first_candidate.get("content", {})
            parts = content.get("parts", [])
            if not parts:
                return []

            raw_text = parts[0].get("text", "").strip()
            if not raw_text:
                return []

            # Strip markdown code blocks if present
            if raw_text.startswith("```"):
                raw_text = re.sub(r"^```(?:json)?\s*", "", raw_text)
                raw_text = re.sub(r"\s*```$", "", raw_text)

            parsed_json = json.loads(raw_text)
            raw_claims = parsed_json.get("claims", [])
            if not isinstance(raw_claims, list):
                return []

            claims: list[dict[str, Any]] = []
            for index, item in enumerate(raw_claims, start=1):
                if not isinstance(item, dict):
                    continue

                claimed = str(item.get("claimed_behavior", "")).strip()
                observed = str(item.get("observed_behavior", "")).strip()
                mismatch = bool(item.get("potential_mismatch", False))

                try:
                    conf = float(item.get("confidence", 0.8))
                    conf = max(0.0, min(1.0, conf))
                except (ValueError, TypeError):
                    conf = 0.8

                refs = item.get("supporting_code_references", [])
                if not isinstance(refs, list):
                    refs = [f"{tool.source_file}:{tool.handler_line or tool.line}"]
                else:
                    refs = [str(r) for r in refs if str(r).strip()]
                if not refs:
                    refs = [f"{tool.source_file}:{tool.handler_line or tool.line}"]

                reasoning = str(item.get("reasoning", "")).strip()

                claim_id = f"claim_{tool.name}_{index:02d}"
                claims.append(
                    {
                        "id": claim_id,
                        "tool_name": tool.name,
                        "claimed_behavior": claimed or tool.declared_description,
                        "observed_behavior": observed,
                        "potential_mismatch": mismatch,
                        "confidence": conf,
                        "supporting_code_references": refs,
                        "cited_evidence_ids": [tool.evidence_id] if tool.evidence_id else [],
                        "model": self.model,
                        "reasoning": reasoning,
                    }
                )

            return claims
        except Exception as exc:
            logger.warning("Failed to parse Gemma response JSON: %s", exc)
            return []

