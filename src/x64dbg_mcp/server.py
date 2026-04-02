from __future__ import annotations

import atexit
import logging
import os
import re
from typing import Any

from mcp.server.fastmcp import FastMCP

from .bridge_server import BridgeError, SessionRegistry


LOG = logging.getLogger(__name__)

HOST = os.environ.get("X64DBG_MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("X64DBG_MCP_PORT", "47063"))
DEFAULT_TIMEOUT = float(os.environ.get("X64DBG_MCP_TIMEOUT", "20"))

registry = SessionRegistry(host=HOST, port=PORT)
registry.start()
atexit.register(registry.stop)

mcp = FastMCP("x64dbg-mcp")

HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
INT_RE = re.compile(r"^-?\d+$")

BP_TYPES = {
    "normal": 1,
    "hardware": 2,
    "memory": 4,
    "dll": 8,
    "exception": 16,
}


def _coerce_int(value: int | str, *, field: str) -> int:
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an int or string")
    text = value.strip()
    if HEX_RE.match(text):
        return int(text, 16)
    if INT_RE.match(text):
        return int(text, 10)
    raise ValueError(f"{field} must be a decimal or hex integer string")


def _call(method: str, params: dict[str, Any] | None = None, *, session_id: str | None, timeout_sec: float | None = None) -> Any:
    return registry.call(session_id=session_id, method=method, params=params or {}, timeout=timeout_sec or DEFAULT_TIMEOUT)


@mcp.tool()
def list_sessions() -> list[dict[str, Any]]:
    """List x64dbg instances currently connected to this MCP server."""
    return registry.list_sessions()


@mcp.tool()
def poll_events(session_id: str | None = None, limit: int = 50, clear: bool = True) -> list[dict[str, Any]]:
    """Return pending debugger events from the connected x64dbg plugin."""
    return registry.poll_events(session_id=session_id, limit=limit, clear=clear)


@mcp.tool()
def session_info(session_id: str | None = None) -> dict[str, Any]:
    """Return debugger and bridge status for the selected x64dbg session."""
    return _call("get_session_info", session_id=session_id)


@mcp.tool()
def execute_command(command: str, session_id: str | None = None, direct: bool = True, timeout_sec: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Execute a raw x64dbg command. This is the escape hatch for the full command bar surface."""
    return _call(
        "exec_command",
        {"command": command, "direct": direct},
        session_id=session_id,
        timeout_sec=timeout_sec,
    )


@mcp.tool()
def sdk_call(method: str, params: dict[str, Any] | None = None, session_id: str | None = None, timeout_sec: float = DEFAULT_TIMEOUT) -> Any:
    """Call a lower-level x64dbg bridge method directly. Use session_info or sdk_call(method='describe_methods') to discover names."""
    return _call(method, params=params, session_id=session_id, timeout_sec=timeout_sec)


@mcp.tool()
def eval_expression(expression: str, session_id: str | None = None) -> dict[str, Any]:
    """Evaluate an x64dbg expression and return the parsed value."""
    return _call("eval", {"expression": expression}, session_id=session_id)


@mcp.tool()
def read_memory(address: int | str, size: int, session_id: str | None = None) -> dict[str, Any]:
    """Read debuggee memory and return a hex string."""
    return _call("read_memory", {"address": _coerce_int(address, field="address"), "size": size}, session_id=session_id)


@mcp.tool()
def write_memory(address: int | str, data_hex: str, session_id: str | None = None) -> dict[str, Any]:
    """Write a hex-encoded byte sequence into debuggee memory."""
    return _call("write_memory", {"address": _coerce_int(address, field="address"), "data_hex": data_hex}, session_id=session_id)


@mcp.tool()
def memory_map(session_id: str | None = None) -> dict[str, Any]:
    """Return the current memory map from x64dbg."""
    return _call("get_memory_map", session_id=session_id)


@mcp.tool()
def disassemble(address: int | str, session_id: str | None = None, fast: bool = False) -> dict[str, Any]:
    """Disassemble one instruction at an address."""
    method = "disasm_fast" if fast else "disasm"
    return _call(method, {"address": _coerce_int(address, field="address")}, session_id=session_id)


@mcp.tool()
def assemble(address: int | str, instruction: str, session_id: str | None = None) -> dict[str, Any]:
    """Assemble one instruction at an address."""
    return _call(
        "assemble_at",
        {"address": _coerce_int(address, field="address"), "instruction": instruction},
        session_id=session_id,
    )


@mcp.tool()
def registers(session_id: str | None = None) -> dict[str, Any]:
    """Return the current register state."""
    return _call("get_regs", session_id=session_id)


@mcp.tool()
def threads(session_id: str | None = None) -> dict[str, Any]:
    """Return the debugger thread list."""
    return _call("get_threads", session_id=session_id)


@mcp.tool()
def breakpoints(kind: str | None = None, session_id: str | None = None) -> dict[str, Any]:
    """List breakpoints. kind may be normal, hardware, memory, dll, or exception."""
    params: dict[str, Any] = {}
    if kind:
        key = kind.lower()
        if key not in BP_TYPES:
            raise ValueError("kind must be one of: normal, hardware, memory, dll, exception")
        params["type"] = BP_TYPES[key]
    return _call("get_breakpoints", params=params, session_id=session_id)


@mcp.tool()
def symbols(
    session_id: str | None = None,
    base: int | str | None = None,
    start: int | str | None = None,
    end: int | str | None = None,
    limit: int = 256,
) -> dict[str, Any]:
    """Enumerate symbols by module base or address range."""
    params: dict[str, Any] = {"limit": limit}
    if base is not None:
        params["base"] = _coerce_int(base, field="base")
    if start is not None:
        params["start"] = _coerce_int(start, field="start")
    if end is not None:
        params["end"] = _coerce_int(end, field="end")
    return _call("enum_symbols", params=params, session_id=session_id, timeout_sec=max(DEFAULT_TIMEOUT, 60.0))


@mcp.tool()
def analyze_function(entry: int | str, session_id: str | None = None, timeout_sec: float = 60.0) -> dict[str, Any]:
    """Return a control-flow graph for a function entry point."""
    return _call(
        "analyze_function",
        {"entry": _coerce_int(entry, field="entry")},
        session_id=session_id,
        timeout_sec=timeout_sec,
    )


@mcp.tool()
def function_info(address: int | str, session_id: str | None = None) -> dict[str, Any]:
    """Return the function metadata covering an address."""
    addr = _coerce_int(address, field="address")
    result = _call("get_function", {"address": addr}, session_id=session_id)
    result["function_type"] = _call("get_function_type", {"address": addr}, session_id=session_id)
    return result


@mcp.tool()
def add_function(start: int | str, end: int | str, session_id: str | None = None) -> dict[str, Any]:
    """Create a manual function in x64dbg."""
    return _call(
        "add_function",
        {"start": _coerce_int(start, field="start"), "end": _coerce_int(end, field="end")},
        session_id=session_id,
    )


@mcp.tool()
def delete_function(address: int | str, session_id: str | None = None) -> dict[str, Any]:
    """Delete a manual function in x64dbg."""
    return _call("del_function", {"address": _coerce_int(address, field="address")}, session_id=session_id)


@mcp.tool()
def annotations(address: int | str, session_id: str | None = None) -> dict[str, Any]:
    """Return label, comment, and bookmark state for one address."""
    addr = _coerce_int(address, field="address")
    return {
        "label": _call("get_label", {"address": addr}, session_id=session_id),
        "comment": _call("get_comment", {"address": addr}, session_id=session_id),
        "bookmark": _call("get_bookmark", {"address": addr}, session_id=session_id),
    }


@mcp.tool()
def set_label(address: int | str, text: str, session_id: str | None = None) -> dict[str, Any]:
    """Set a user label at an address."""
    return _call("set_label", {"address": _coerce_int(address, field="address"), "text": text}, session_id=session_id)


@mcp.tool()
def set_comment(address: int | str, text: str, session_id: str | None = None) -> dict[str, Any]:
    """Set a user comment at an address."""
    return _call("set_comment", {"address": _coerce_int(address, field="address"), "text": text}, session_id=session_id)


@mcp.tool()
def set_bookmark(address: int | str, enabled: bool = True, session_id: str | None = None) -> dict[str, Any]:
    """Set or clear a bookmark at an address."""
    return _call("set_bookmark", {"address": _coerce_int(address, field="address"), "enabled": enabled}, session_id=session_id)


def main() -> None:
    logging.basicConfig(level=os.environ.get("X64DBG_MCP_LOG", "INFO").upper())
    try:
        mcp.run()
    except BridgeError as exc:
        LOG.error("%s", exc)
        raise


if __name__ == "__main__":
    main()
