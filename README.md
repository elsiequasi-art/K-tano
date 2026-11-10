# K-tano — Aegis Ethical Security Assistant

Aegis is a Windows desktop AI assistant for authorized, defensive security work. Its task modes cover code and configuration review, threat modeling, incident triage, vulnerability explanations, hardening plans, and safe learning exercises.

The app analyzes text you provide or explicitly choose to open. Its local tools are user-triggered: three fixed read-only diagnostics, a single-IP TCP connect check capped at 32 ports, and a button to open installed Wireshark. Each diagnostic uses a structured allowlist entry with a fixed absolute executable path and argument list, and streams stdout to the console buffer. Every diagnostic, scan, and Wireshark launch asks the user to confirm authorization. It does not execute arbitrary AI-generated commands, accept free-form command arguments, use stealth modes, or modify reviewed files. Wireshark capture interfaces and start/stop controls remain in Wireshark.

The user may also enable live web search per request before clicking Send. Search options include an exact query, optional allowed hostnames (up to 10), and low, medium, or high search context. The default is low for focused results. Search-enabled answers display clickable inline citations and source links. Web search is limited to research; it does not probe or scan targets.

## Windows setup

Requirements: Windows 10 or 11, Python 3.10 or newer with Tkinter for building from source, an OpenAI API key, and internet access for model requests.

To build and install from source:

1. Open PowerShell in this repository.
2. Run **.\build_windows.ps1** to create **dist\Aegis.exe**.
3. Run **.\install_windows.ps1** to install Aegis for the current user and add a Start menu shortcut.

The build uses PyInstaller from **requirements-build.txt** in a project-local virtual environment. No administrator access is required.

## API key and privacy

Aegis does not include or save an API key. Enter a key in the app for the current session or set **OPENAI_API_KEY** before launching. The key is not written to settings or source files.

Your prompt, selected file text, and recent conversation context are sent to the OpenAI Responses API only after you click Send. If live web search is enabled, the request also invokes OpenAI's hosted web search and applies the optional domain filters. Local diagnostic output stays on this PC unless you choose Use last tool result and then click Send. Requests set response storage to false, and Aegis does not save conversation history locally. Provider policies still govern data handling and retention; API usage may incur charges. Do not submit credentials, private keys, personal data, or material you are not allowed to share.

This build is intended for one person's local use with their own API key. Do not embed or distribute a personal key with the app. A multi-user service would need a trusted server-side credential design.

## Task modes

- General security assistant
- Code review
- Configuration review
- Threat model
- Incident triage
- Vulnerability explanation
- Hardening plan
- Learning lab

Use Add text file to load a source, log, or configuration file up to 256 KiB. Nothing is sent until you click Send. For precise current research, enable web search, enter an optional exact query, restrict allowed hostnames if helpful, and choose source detail. Save the latest answer as a Markdown or text report; search sources are included as links.

## Safety boundary

Aegis is advisory software with limited, explicit local controls, not an autonomous penetration-testing engine. The TCP check accepts one literal IP and up to 32 comma-separated ports, and requires an authorization checkbox plus a fresh confirmation dialog. It makes sequential TCP connection attempts only; it does not perform UDP scans, service enumeration, stealth, exploitation, or broad-range scanning. The fixed local diagnostics and Wireshark launcher also ask for authorization. The AI cannot trigger these controls.

The complete assistant persona is in [PERSONA.md](PERSONA.md).


