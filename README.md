# Aegis Desktop — Ethical Security Assistant

Aegis is a Windows desktop client for authorized, defensive security work. It provides task modes for code and configuration review, threat modeling, incident triage, vulnerability explanations, hardening plans, safe learning exercises, and user-triggered web research.

The app analyzes text you provide or explicitly choose to open. Its assessment dashboard adds a bounded single-IP TCP connect check, explicitly authorized HTTP(S) endpoint checks using HEAD, OPTIONS, GET, or a sequential three-method suite, and local Python static heuristics. Local commands remain fixed read-only diagnostics, and the app does not execute arbitrary commands or modify reviewed files.

## Requirements

- Windows 10 or 11
- An OpenAI API key and access to a text-capable API model
- Internet access for model requests and optional web search

Aegis does not include or store an API key. You can enter one for the current session or set the OPENAI_API_KEY environment variable before launching. The key is held in memory by the app and is never written to its settings or source files.

## Build and install

1. Install Python 3.10 or newer with Tkinter.
2. Open PowerShell in this folder.
3. Run .\build_windows.ps1. This creates a self-contained dist\Aegis.exe.
4. Run .\install_windows.ps1 to copy Aegis into your per-user Programs folder and add a Start menu shortcut.

The build script downloads PyInstaller into a project-local virtual environment. It does not require administrator access.

## Use

- Choose a task mode, such as Code review or Threat model.
- Paste text or use Add text file to load a source, log, or configuration file up to 256 KiB.
- Review the request, then click Send. Nothing is sent before that action.
- For current research, enable **Search the live web for this request** before clicking Send. Enter an exact search query if useful, restrict results to up to 10 hostnames (for example, `nist.gov, cisa.gov`), and choose low, medium, or high source detail. Low is the focused default.
- Search-enabled responses show clickable inline citations and a clickable source list. Source detail controls how much search context the model receives; it does not guarantee an exact number of sources.
- Save the latest answer as a Markdown or text report.
- Use Clear session to remove the visible conversation and in-memory history.

Aegis sends the request and selected conversation context to the OpenAI Responses API with response storage disabled. If web search is enabled, the request uses OpenAI's hosted live web search and any configured domain filters. Provider policies still govern handling and retention, and API usage may incur charges. Do not submit credentials, private keys, personal data, or material you are not allowed to share.

## Assessment dashboard

- **TCP discovery:** one literal IP and up to 32 explicitly entered TCP ports. Each run shows the exact scope and requires a fresh authorization confirmation.
- **Endpoint signatures:** one exact HTTP(S) URL with HEAD, OPTIONS, GET, or a sequential suite of those three methods. GET may invoke application logic; Aegis reads response headers only. It sends no credentials, query strings, request body, redirects, crawls, or test payloads. A counter-test repeats the same method(s) and compares findings; every run requires fresh authorization.
- **Python analysis:** choose one `.py` file up to 256 KiB. A local AST and pattern engine flags selected risky APIs, possible hard-coded secrets (values are withheld), unbounded loops, nested loops, and regex compilation inside loops. It never executes the file. Findings are heuristics for review, not proof of a vulnerability or performance defect.
- **Audit and remediation:** findings and action logs can be exported as Markdown or JSON. The dashboard can save Nginx, Apache, or IIS configuration drafts and prepare an AI patch request. Saving asks for confirmation; AI requests require a separate Send click. Drafts are not applied or executed.

The active checks are intentionally bounded to one IP/port list or one endpoint. They do not enumerate hosts, crawl sites, attempt exploits, or perform stealth activity. The Python analyzer never executes user-selected source; dynamic behavior tests for source code require a separate sandbox and are not part of this desktop build. Use active checks only on assets you own or are explicitly authorized to assess.

## Safety boundary

Aegis is an advisory assistant, not a penetration-testing engine. It is designed for scoped, authorized security work and refuses actionable help for credential theft, malware, persistence, evasion, exfiltration, destructive activity, and unauthorized access. Live web searches occur only when the user enables the option and clicks Send. Search is limited by optional hostname filters and never probes or scans a target. Local commands remain a fixed allowlist and require explicit authorization; arbitrary AI-generated commands and stealth scans are excluded.

See PERSONA.md for the complete system prompt.


