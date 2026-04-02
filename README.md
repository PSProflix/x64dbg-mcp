# x64dbg MCP

`x64dbg-mcp` is a two-part bridge:

1. A native x64dbg plugin that runs inside the debugger and exposes debugger state, memory, symbols, annotations, xrefs, threads, registers, and function analysis.
2. A Python MCP server that any stdio-compatible MCP client can launch, including AI tools that support MCP such as Claude Code, Gemini CLI/Desktop integrations, Codex, and similar clients.

The plugin also forwards debugger lifecycle events like attach, breakpoints, pause/resume, DLL loads, thread creation, and exceptions.

## What it exposes

- Raw x64dbg command execution through `execute_command`
- Lower-level bridge methods through `sdk_call`
- Memory read/write and memory map inspection
- Register, thread, breakpoint, and watch-list inspection
- Labels, comments, bookmarks, and auto-annotations
- Function, argument, and loop metadata
- Xrefs, strings, symbols, and CFG analysis via `DbgAnalyzeFunction`
- Event polling for debugger activity

The Python side includes dedicated MCP tools for the common workflows and keeps a generic `sdk_call` tool for less-common methods.

## Project layout

- `plugin/src/pluginmain.cpp`
- `plugin/CMakeLists.txt`
- `src/x64dbg_mcp/server.py`
- `src/x64dbg_mcp/bridge_server.py`
- `vendor/pluginsdk`

## Build the plugin

Requirements:

- Visual Studio Build Tools or Visual Studio with C++ support
- CMake
- x64dbg target installation

Build x64:

```powershell
cd C:\Users\Pai\Desktop\x64dbg-mcp
.\plugin\build.ps1 -Arch x64 -Config Release
```

Build x86:

```powershell
cd C:\Users\Pai\Desktop\x64dbg-mcp
.\plugin\build.ps1 -Arch Win32 -Config Release
```

The build outputs:

- `build\plugin\x64\dist\x64dbg_mcp.dp64`
- `build\plugin\Win32\dist\x64dbg_mcp.dp32`

Copy them into your x64dbg plugin folders:

- `x64dbg\release\x64\plugins\x64dbg_mcp.dp64`
- `x64dbg\release\x32\plugins\x64dbg_mcp.dp32`

## Install the MCP server

```powershell
cd C:\Users\Pai\Desktop\x64dbg-mcp
python -m pip install -e .
```

The server listens for the x64dbg plugin on `127.0.0.1:47063` by default.

Optional environment variables:

- `X64DBG_MCP_HOST`
- `X64DBG_MCP_PORT`
- `X64DBG_MCP_TIMEOUT`
- `X64DBG_MCP_LOG`

Use the same `X64DBG_MCP_HOST` and `X64DBG_MCP_PORT` values in the environment that launches x64dbg if you want a non-default socket.

## Generic MCP client config

Any stdio MCP client can launch the server with:

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "python",
      "args": ["-m", "x64dbg_mcp"]
    }
  }
}
```

## Typical workflow

1. Start the MCP client so the Python server is running.
2. Launch x64dbg with the plugin installed.
3. Open or attach the target in x64dbg.
4. Call `list_sessions` and `session_info`.
5. Use `execute_command`, `disassemble`, `read_memory`, `registers`, `function_info`, `analyze_function`, or `sdk_call`.
6. Call `poll_events` to see breakpoint hits, exceptions, DLL loads, and pause/resume activity.

## Low-level bridge methods

Use `sdk_call(method=..., params=...)` for the plugin dispatcher. Current low-level methods include:

- `describe_methods`
- `get_session_info`
- `wait_until_paused`
- `exec_command`
- `eval`
- `read_memory`
- `write_memory`
- `get_memory_map`
- `find_base`
- `module_at`
- `mod_base_from_name`
- `is_valid_read_ptr`
- `disasm`
- `disasm_fast`
- `assemble_at`
- `get_regs`
- `get_threads`
- `get_breakpoints`
- `get_watch_list`
- `get_label`
- `set_label`
- `clear_label_range`
- `get_comment`
- `set_comment`
- `clear_comment_range`
- `get_bookmark`
- `set_bookmark`
- `clear_bookmark_range`
- `get_function_type`
- `get_function`
- `function_overlaps`
- `add_function`
- `del_function`
- `get_argument_type`
- `get_argument`
- `argument_overlaps`
- `add_argument`
- `del_argument`
- `get_loop_type`
- `get_loop`
- `loop_overlaps`
- `add_loop`
- `del_loop`
- `set_auto_comment`
- `clear_auto_comment_range`
- `set_auto_label`
- `clear_auto_label_range`
- `set_auto_bookmark`
- `clear_auto_bookmark_range`
- `set_auto_function`
- `clear_auto_function_range`
- `add_xref`
- `del_all_xrefs`
- `get_xrefs`
- `get_xref_count`
- `get_xref_type`
- `get_string_at`
- `get_symbol_at`
- `enum_symbols`
- `analyze_function`
- `update_gui`

## Notes

- This project vendors the x64dbg plugin SDK in `vendor/pluginsdk` so the plugin build is self-contained.
- The MCP server is transport-neutral on the client side: any AI or tool that can launch stdio MCP can use it.
- The raw command path means you still have access to the broader x64dbg command surface even if a dedicated structured wrapper is missing.

## Verification limits

- I implemented the Python server and plugin source in this environment.
- I could not build the plugin here because this machine does not have `cmake` or a C++ compiler in `PATH`.
