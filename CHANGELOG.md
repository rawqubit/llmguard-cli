# Changelog

All notable changes to **llmguard-cli** are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) | Versioning: [SemVer](https://semver.org/)

## [1.2.0] - 2025-03-15
### Added
- HTTP API server mode (`llmguard serve`) for inline LLM pipeline integration
- Batch scanning via JSONL file input for red-teaming workflows
- MITRE ATLAS alignment for threat categorization output
- `--no-ai` flag for heuristics-only, ultra-low-latency mode

### Changed
- Upgraded meta-reasoning layer to GPT-4.1
- Reduced false-positive rate on code snippets with injection-like patterns

## [1.1.0] - 2025-01-20
### Added
- 20+ heuristic signatures covering major prompt injection and jailbreak patterns
- 6 threat categories with per-category severity scoring
- CI/CD integration: exits with code 1 on detected threats
- Configurable sensitivity via `--threshold` flag

## [1.0.0] - 2024-11-01
### Added
- Initial release: hybrid heuristic + LLM meta-reasoning detection pipeline
- CLI interface with `--input` and `--output` options
- Rich terminal threat visualization
