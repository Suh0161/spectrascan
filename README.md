# SpectraScan

A comprehensive CLI tool for web endpoint detection combining static JavaScript scanning, dynamic runtime capture, source-map recovery, and complete code extraction.

## Features

- **Static Scanning**: Regex-based endpoint extraction from JavaScript files
- **Dynamic Capture**: Playwright-based runtime network monitoring
- **Source Map Recovery**: Maps minified code to original TypeScript/TSX/JSX sources
- **Code Extraction**: End-to-end crawling with complete source file extraction (HTML, CSS, JS, TS, TSX, JSX)
- **Hybrid Analysis**: Merges static and dynamic discoveries with intelligent deduplication
- **Protocol Detection**: GraphQL, WebSocket, SSE (Server-Sent Events)
- **Auto-Generated Outputs**: HAR files, OpenAPI v3, Postman collections, Python API client stubs
- **Security**: Automatic auth detection and token redaction

## Security & Legal Disclaimer

**IMPORTANT: USE AT YOUR OWN RISK. THE AUTHORS AND CONTRIBUTORS ARE NOT RESPONSIBLE FOR ANY MISUSE OF THIS TOOL.**

### Intended Use

This tool is designed **ONLY** for:
- Security research and penetration testing **with explicit written permission**
- Testing your own applications and systems
- API documentation analysis for authorized systems
- Educational and research purposes
- Developer tooling on systems you own or have permission to test

### Prohibited Use

**DO NOT** use this tool for:
- Unauthorized access to systems
- Exploitation of vulnerabilities without permission
- Data exfiltration or theft
- Any illegal activities
- Violating terms of service
- Accessing systems without explicit authorization

### Legal Notice

- **No Warranty**: This tool is provided "as is" without warranty of any kind
- **No Liability**: The authors, contributors, and maintainers are not liable for any damages, legal issues, or consequences resulting from the use or misuse of this tool
- **User Responsibility**: Users are solely responsible for ensuring they have proper authorization before using this tool
- **Compliance**: Users must comply with all applicable laws, regulations, and terms of service
- **Security Research**: If used for security research, ensure you have written authorization and follow responsible disclosure practices

**By using this tool, you acknowledge that you understand and agree to these terms.**

## Installation

### Prerequisites

- Python 3.8+
- Playwright browsers

### Setup

```bash
# Install Python dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium
```

## Usage

SpectraScan is a command-line tool that can be used in two modes:

### Interactive Mode (CLI)

```bash
python main.py
```

Paste URLs (one per line), type `done` when finished, then choose scan options:
- **Quick**: Fast scan with dynamic capture (7s)
- **Full**: Complete scan with all outputs
- **Custom**: Configure individual settings
- **Code extraction only**: Extract all source code files

### Command-Line Interface (CLI)

```bash
# Single URL
python main.py https://example.com

# Multiple URLs (batch mode)
python main.py https://example.com https://example2.com

# Quick scan
python main.py https://example.com --quick

# Full scan with all outputs
python main.py https://example.com \
  --dynamic \
  --duration 10 \
  --sourcemaps \
  --har out.har \
  --openapi openapi.yaml \
  --postman postman.json \
  --client api_client.py

# Code extraction
python main.py https://example.com --extract-code

# Code extraction with custom crawl settings
python main.py https://example.com --extract-code --max-pages 100 --crawl-depth 5
```

## Command-Line Options

### Core Options

- `urls` - Target URL(s) to scan (can specify multiple)
- `--output`, `-o` - Output JSON file (default: `scan_results.json`)
- `--interactive`, `-i` - Start interactive mode

### Scan Options

- `--dynamic`, `-d` - Enable Playwright runtime capture
- `--duration <seconds>` - Network recording duration (default: 7)
- `--headful` - Run browser with visible window
- `--quick` - Quick scan mode (dynamic + 7s duration)
- `--max-js-size <bytes>` - Maximum JS file size (default: 10MB)

### Source Maps

- `--sourcemaps` - Fetch and apply source maps (default: enabled)
- `--no-sourcemaps` - Disable source map fetching

### Code Extraction

- `--extract-code` - Extract all source code files with semantic labeling
- `--max-pages <count>` - Maximum pages to crawl (default: 50)
- `--crawl-depth <depth>` - Maximum crawl depth (default: 3)

### Output Options

- `--har <path>` - Write HAR file
- `--openapi <path>` - Generate OpenAPI v3 specification (YAML)
- `--postman <path>` - Generate Postman collection (JSON)
- `--client <path>` - Generate Python API client

### Security

- `--no-sensitive-data` - Redact sensitive data (auth tokens, cookies)

## Output Format

Results are saved to `scan_results/` directory by default. The main JSON output contains:

- `target` - Scanned URL
- `fetched_at` - Timestamp
- `static` - Static scan results (endpoints, JS files)
- `dynamic` - Runtime capture results (requests, responses, websockets)
- `sourcemaps` - Source map recovery data
- `merged_endpoints` - Deduplicated endpoints with inferred schemas
- `source_code` - Complete extracted source files organized by language

## Architecture

### Modules

- `detector/scanners.py` - Static JavaScript scanning
- `detector/dynamic.py` - Playwright runtime capture
- `detector/sourcemap.py` - Source map fetching and mapping
- `detector/code_extractor.py` - Complete code extraction with crawling
- `detector/hybrid.py` - Merges static + dynamic + sourcemap results
- `detector/openapi_gen.py` - OpenAPI v3 generation
- `detector/postman_gen.py` - Postman collection generation
- `detector/writer.py` - HAR export and API client generation

### Workflow

1. **Static Pass**: Fetch HTML, extract JS URLs, scan for endpoints
2. **Source Map Recovery**: Download `.map` files, map to original sources
3. **Dynamic Pass**: Load page in Playwright, capture network activity
4. **Code Extraction**: Crawl all pages, extract all source files
5. **Hybrid Analysis**: Merge discoveries, deduplicate, infer schemas
6. **Output Generation**: Create HAR, OpenAPI, Postman, and client stubs

## Protocol Detection

- **GraphQL**: Detects `gql` template literals and GraphQL request patterns
- **WebSocket**: Captures `new WebSocket(url)` and Playwright websocket events
- **SSE**: Detects `new EventSource(url)` calls

## Authentication Detection

Automatically detects:
- Bearer tokens (`Authorization: Bearer ...`)
- API keys (common headers like `X-API-Key`)
- Basic auth
- Cookie-based auth

## Troubleshooting

### Playwright Not Found

```bash
pip install playwright
playwright install chromium
```

### Browser Launch Errors (Linux)

```bash
playwright install-deps
```

## Performance

- **Duration**: Default 7s runtime capture; increase for SPAs with lazy loading
- **Concurrency**: JS file downloads are limited to prevent overwhelming servers
- **Size Limits**: Large JS files (>10MB by default) are skipped
- **Storage**: HAR files and request bodies can be large; use `--no-sensitive-data` to reduce size

## License

MIT License - See LICENSE file for details

---

## Disclaimer

**USE AT YOUR OWN RISK. THE AUTHORS ARE NOT RESPONSIBLE FOR ANY MISUSE OR DAMAGES.**

This tool is for authorized security testing and research purposes only. Users are solely responsible for ensuring they have proper authorization before scanning any systems. The authors, contributors, and maintainers disclaim all liability for any misuse, damages, or legal consequences resulting from the use of this tool.
