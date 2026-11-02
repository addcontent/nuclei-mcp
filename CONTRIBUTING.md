# Contributing to nuclei-mcp

Thanks for helping. Bug reports, docs fixes and code are all welcome.

## Reporting bugs

Open an issue with the version (`nuclei-mcp --version`), your client, the
tool call (arguments) and what you expected. Security problems go through
[SECURITY.md](SECURITY.md), not public issues.

## Development setup

You need Go 1.26 or newer (the Nuclei SDK requires it).

```bash
git clone https://github.com/addcontent/nuclei-mcp
cd nuclei-mcp
go test -race ./...
go build ./cmd/nuclei-mcp
npx @modelcontextprotocol/inspector ./nuclei-mcp   # try it by hand
```

For live testing against your own lab, set
`NUCLEI_MCP_SECURITY_ALLOW_PRIVATE_TARGETS=true`.

## Layout

| Package | Role |
| --- | --- |
| `cmd/nuclei-mcp` | Flags, wiring, stdio transport |
| `pkg/api` | MCP tools and resources |
| `pkg/scanner` | Builds Nuclei SDK options and runs scans |
| `pkg/scope` | Decides which targets may be scanned |
| `pkg/templates` | Template directory access (`os.Root`), validation, built-ins |
| `pkg/cache` | Stored scan results |
| `pkg/config`, `pkg/logging` | Settings and logs |

## Pull requests

1. One fix or feature per PR, with tests. Scanner tests use the fake engine
   in `pkg/scanner/scanner_test.go`; API tests call the real server with
   JSON-RPC in `pkg/api/server_test.go`.
2. `gofmt -l .` prints nothing, `go vet ./...` and `go test -race ./...` pass
   (CI checks all three, plus `govulncheck`).
3. Update `README.md` and `config.example.yaml` when you change a tool or a
   setting.
4. Never log or write anything to stdout: it carries the MCP protocol.

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Contributions are licensed under the MIT License (see LICENSE).
