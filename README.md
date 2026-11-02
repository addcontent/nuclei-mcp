# nuclei-mcp

An [MCP](https://modelcontextprotocol.io) server that lets AI assistants run
[Nuclei](https://github.com/projectdiscovery/nuclei) vulnerability scans. It
embeds the Nuclei Go SDK, so it is a single binary: nothing else to install.

> **Only scan systems you own or are authorized to test.** Scans send real,
> sometimes intrusive, traffic.

## Features

- `nuclei_scan` with minimum-severity, protocol, template ID and tag filters
- `basic_scan` for a quick "does it answer HTTP" check
- paged, structured findings (template ID, severity, matched URL, CVE, CVSS,
  extracted values, references), with `get_scan_results` to read further
- built-in starter templates; point it at the official
  [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)
  tree for full coverage
- safe defaults: internal and cloud-metadata targets refused, template writes
  off, out-of-band callbacks off, rate limits on

## Install

**Release binary:** download the archive for your platform from the
[Releases page](https://github.com/addcontent/nuclei-mcp/releases) and put
`nuclei-mcp` (`nuclei-mcp.exe` on Windows) on your `PATH`.

**Go 1.26+:**

```bash
go install github.com/addcontent/nuclei-mcp/cmd/nuclei-mcp@latest
```

**Docker:**

```bash
docker build -t nuclei-mcp .
docker run -i --rm nuclei-mcp      # -i is required: MCP runs over stdin/stdout
```

On first start the built-in templates are copied to
`~/.nuclei-mcp/templates`; existing files there are never overwritten.

## Connect a client

Claude Desktop (`claude_desktop_config.json`), Cursor, VS Code and other MCP
clients take a command to launch:

```json
{
  "mcpServers": {
    "nuclei": {
      "command": "/usr/local/bin/nuclei-mcp",
      "env": {
        "NUCLEI_MCP_SECURITY_ALLOW_PRIVATE_TARGETS": "false"
      }
    }
  }
}
```

With Docker, use `"command": "docker", "args": ["run", "-i", "--rm", "nuclei-mcp"]`.

To try it interactively:

```bash
npx @modelcontextprotocol/inspector nuclei-mcp
```

## Tools and resources

| Name | What it does |
| --- | --- |
| `nuclei_scan` | Scan one target. `severity` is a minimum (`high` = high + critical) or an exact list (`low,high`); `protocols` (`http`, `dns`, `ssl`, `tcp`, `websocket`, `whois`, `javascript`; `https` means `http`); `template_ids`, `tags`, `exclude_tags`; `limit`/`offset` for paging |
| `basic_scan` | Run only the basic template against a target |
| `get_scan_results` | Page through a stored scan by `scan_id`, optionally by minimum severity |
| `list_templates` | List installed templates, optionally filtered |
| `get_template` | Show one template's YAML |
| `add_template` | Save a new template. **Only registered when `security.allow_template_writes` is true** |
| `nuclei://scans` | Resource: recent scans, newest first |
| `nuclei://scans/{scan_id}` | Resource template: every finding of one scan |

Bare hosts (`example.com`) are probed for HTTP/HTTPS; URLs with a scheme are
scanned as given. Every failure comes back as a tool error the model can read
and correct.

## Configuration

All settings are optional. Lookup order for the file: `--config <path>`, then
`./config.yaml`, `~/.nuclei-mcp/config.yaml`, `/etc/nuclei-mcp/config.yaml`.
Every key can also be set from the environment: `NUCLEI_MCP_` plus the key
path in upper case, dots as underscores, e.g. `NUCLEI_MCP_LOGGING_LEVEL=debug`
or `NUCLEI_MCP_SECURITY_ALLOWED_TARGETS=example.com,*.example.org`.
`NUCLEI_MCP_HOME` moves the default directory away from `~/.nuclei-mcp`.

See [`config.example.yaml`](config.example.yaml) for every key with its
default. The ones you are most likely to change:

| Key | Default | Meaning |
| --- | --- | --- |
| `nuclei.templates_directory` | `~/.nuclei-mcp/templates` | Templates to scan with (whole tree) |
| `nuclei.scan_timeout` | `10m` | A scan stops here and returns partial results |
| `nuclei.rate_limit` | `150` | Requests per second |
| `security.allow_private_targets` | `false` | Allow loopback, private and link-local targets (your lab) |
| `security.allowed_targets` | `[]` | If set, only these hosts, `*.domains`, IPs or CIDRs |
| `security.denied_targets` | `[]` | Always refused |
| `security.interactsh` | `false` | Out-of-band callbacks via public interactsh servers |
| `security.allow_template_writes` | `false` | Expose `add_template` |
| `logging.path` | `~/.nuclei-mcp/logs/nuclei-mcp.log` | Empty = stderr only |

To use the official templates:

```bash
git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates ~/nuclei-templates
NUCLEI_MCP_NUCLEI_TEMPLATES_DIRECTORY=~/nuclei-templates nuclei-mcp
```

## Security model

The model, not you, picks every tool argument, and text it reads (a web page,
an issue) can steer it. So the server limits what a steered model can do:

- **Targets:** loopback, private, link-local, CGNAT and `localhost` targets
  are refused unless `allow_private_targets` is on; cloud metadata endpoints
  (`169.254.169.254` and friends) are refused unless listed in
  `allowed_targets`. Nuclei's own local-network restriction backs this up.
- **Templates:** all template file access is confined to the templates
  directory with `os.Root` (no `../`, absolute paths or symlink escapes).
  `add_template` is off by default; when on, it only accepts network
  templates (no `code`, `javascript`, `flow`, `headless`, `file`,
  `workflows`, self-contained templates or `@Host`) and never overwrites.
- **Traffic:** rate limits apply; interactsh callbacks are off by default.
- **Annotations:** tools carry MCP read-only / open-world hints so clients
  can ask before scanning.

Report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Development

```bash
go vet ./...
go test -race ./...
go build ./cmd/nuclei-mcp
```

Tests use a fake Nuclei engine and drive the real MCP server with JSON-RPC,
so they need no network. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT; see [LICENSE](LICENSE). Built on
[Nuclei](https://github.com/projectdiscovery/nuclei) and
[mcp-go](https://github.com/mark3labs/mcp-go).
