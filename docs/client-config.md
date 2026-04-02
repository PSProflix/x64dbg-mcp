# MCP Client Config

Minimal stdio config:

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

If your MCP client supports environment overrides:

```json
{
  "mcpServers": {
    "x64dbg": {
      "command": "python",
      "args": ["-m", "x64dbg_mcp"],
      "env": {
        "X64DBG_MCP_PORT": "47063",
        "X64DBG_MCP_LOG": "INFO"
      }
    }
  }
}
```
