"""Defense against prompt injection from evidence content.

Every tool stdout the gateway returns to the orchestrator passes through this
module. Inline LLM-vendor delimiters are escaped, then the whole payload is
wrapped in <evidence ...> tags whose attributes are unforgeable (they come
from the gateway-issued invocation_id and tool name).

The system prompt instructs the orchestrator that content inside <evidence>
tags is data, never instructions. The architectural piece is the wrap and
the escape, which hold regardless of what the system prompt says.
"""

from __future__ import annotations

import re

# Tags an attacker might inject into a log line to try to drive the LLM.
# Escaping them with a leading marker breaks the role/turn structure.
DENY_TAGS: tuple[str, ...] = (
    "system",
    "assistant",
    "user",
    "tool_use",
    "tool_result",
    "function_calls",
    "function_results",
    "invoke",
    "parameter",
    "antml:parameter",
    "antml:invoke",
    "antml:function_calls",
    "instructions",
    "prompt",
    "role",
    "stop_sequences",
    "human",
    "claude",
    "im_start",
    "im_end",
    "endoftext",
)

_TAG_PATTERN = re.compile(
    r"<(/?\s*(?:" + "|".join(DENY_TAGS) + r")\b[^>]*)>",
    flags=re.IGNORECASE,
)


def _escape_inline_tags(text: str) -> str:
    """Replace `<tag ...>` with `[esc:tag ...]` so the LLM tokenizer does
    not interpret them as role/tool delimiters.
    """
    return _TAG_PATTERN.sub(lambda m: "[esc:" + m.group(1) + "]", text)


def sanitize_for_llm(text: str) -> str:
    """Strip control characters except whitespace and escape vendor delimiters."""
    # Keep \t, \n, \r; replace other C0/C1 control chars with spaces.
    cleaned_chars = []
    for ch in text:
        cp = ord(ch)
        if cp in (0x09, 0x0A, 0x0D) or 0x20 <= cp < 0x7F:
            cleaned_chars.append(ch)
        elif 0x80 <= cp < 0xA0:
            cleaned_chars.append(" ")
        elif cp < 0x20:
            cleaned_chars.append(" ")
        else:
            cleaned_chars.append(ch)
    return _escape_inline_tags("".join(cleaned_chars))


def wrap_evidence(
    *,
    body: str,
    tool: str,
    invocation_id: str,
    truncated: bool = False,
    bytes_seen: int = 0,
) -> str:
    """Wrap a tool stdout for safe presentation to the orchestrator.

    The wrapper is on the GATEWAY side, so the attribute values cannot be
    forged by the LLM or by evidence content.
    """
    safe = sanitize_for_llm(body)
    flag = " truncated=\"true\"" if truncated else ""
    return (
        f'<evidence tool="{tool}" invocation_id="{invocation_id}" '
        f'bytes_seen="{bytes_seen}"{flag}>\n'
        f"{safe}\n"
        f"</evidence>"
    )


__all__ = ["wrap_evidence", "sanitize_for_llm", "DENY_TAGS"]
