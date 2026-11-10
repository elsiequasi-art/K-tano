# Aegis Desktop — Ethical Security Assistant

Aegis is a Windows desktop client for authorized, defensive security work. It provides task modes for code and configuration review, threat modeling, incident triage, vulnerability explanations, hardening plans, safe learning exercises, and user-triggered web research.

The app analyzes text you provide or explicitly choose to open. Its assessment dashboard adds a bounded single-IP TCP connect check, explicitly authorized HTTP(S) endpoint checks using HEAD, OPTIONS, GET, or a sequential three-method suite, local Python static heuristics, and parameterized Python tests inside Docker Desktop's Linux VM. Local commands remain fixed read-only diagnostics; dynamic tests execute only the selected project inside the isolated container, and Aegis does not run generated shell commands or modify reviewed files.

## Requirements

- Windows 10 or 11
- An OpenAI API key and access to a text-capable API model
- Internet access for model requests and optional web search
- Docker Desktop with the `desktop-linux` context for dynamic Python suites (static analysis and the other dashboard tools do not need Docker)

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
- **Python analysis and dynamic tests:** static analysis reads one `.py` file up to 256 KiB and flags selected risky APIs, possible hard-coded secrets (values are withheld), and loop/performance heuristics. For dynamic tests, choose a project folder, entry module, and JSON suite based on `test-suite.example.json`. Aegis stages a filtered copy of supported source and text files, skipping known secret names and common environment folders, then mounts it read-only in the Docker Desktop `desktop-linux` context. Each case imports the selected module in a fresh Python process, instantiates a selected class or calls a selected function, passes JSON `args`/`kwargs`, checks an optional expected exception/return, and captures bounded output and exception traces. The container has networking disabled, a read-only root filesystem, no added Linux capabilities, an unprivileged user, 256 MiB memory, one CPU, 32 processes, a five-second per-case limit, a 110-second overall limit, and bounded output. The original project is not modified. Dynamic execution requires Docker Desktop with its Linux VM running; the first run asks separately before downloading the official Python image. Python dependencies are not installed in the container; use standard-library dependencies or include importable source in the staged project. Container and VM isolation reduce host exposure but cannot protect against a vulnerability in Docker Desktop, its VM, or the host kernel.
- **Audit and remediation:** findings and action logs can be exported as Markdown or JSON. The dashboard can save Nginx, Apache, or IIS configuration drafts and prepare an AI patch request. Saving asks for confirmation; AI requests require a separate Send click. Drafts are not applied or executed.

The active checks are intentionally bounded to one IP/port list or one endpoint. They do not enumerate hosts, crawl sites, attempt exploits, or perform stealth activity. Dynamic Python tests run only after an authorization checkbox and a fresh confirmation show the selected project, entry module, and suite. They execute the selected project code inside the isolated container; use only code you are authorized to run. Use network checks only on assets you own or are explicitly authorized to assess.

## Safety boundary

Aegis is an advisory assistant, not a penetration-testing engine. It is designed for scoped, authorized security work and refuses actionable help for credential theft, malware, persistence, evasion, exfiltration, destructive activity, and unauthorized access. Live web searches occur only when the user enables the option and clicks Send. Search is limited by optional hostname filters and never probes or scans a target. Local commands remain a fixed allowlist and require explicit authorization; arbitrary AI-generated commands and stealth scans are excluded.

See PERSONA.md for the complete system prompt.


