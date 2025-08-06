#!/bin/bash
WORKSPACE_ROOT="~/code/foo"

cd $WORKSPACE_ROOT

claude mcp add-json adversary '{
  "command": "uv",
  "args": [
    "run",
    "--directory",
    "~/code/adversary-mcp-server",
    "python",
    "-m",
    "adversary_mcp_server.server"
  ],
  "env": {
    "ADVERSARY_WORKSPACE_ROOT": "$WORKSPACE_ROOT"
  }
}'
