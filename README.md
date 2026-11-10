# K-tano — Aegis Ethical Security Assistant

Aegis is a Windows desktop AI assistant for authorized, defensive security work. Its task modes cover code and configuration review, threat modeling, incident triage, vulnerability explanations, hardening plans, and safe learning exercises.

The app analyzes only text you provide or explicitly choose to open. It does not run shell commands, scan networks, or modify reviewed files.

## Windows setup

Requirements: Windows 10 or 11, Python 3.10 or newer with Tkinter for building from source, an OpenAI API key, and internet access for model requests.

To build and install from source:

1. Open PowerShell in this repository.
2. Run **.\build_windows.ps1** to create **dist\Aegis.exe**.
3. Run **.\install_windows.ps1** to install Aegis for the current user and add a Start menu shortcut.

The build uses PyInstaller from **requirements-build.txt** in a project-local virtual environment. No administrator access is required.

## API key and privacy

Aegis does not include or save an API key. Enter a key in the app for the current session or set **OPENAI_API_KEY** before launching. The key is not written to settings or source files.

Your prompt, selected file text, and recent conversation context are sent to the OpenAI Responses API only after you click Send. Requests set response storage to false, and Aegis does not save conversation history locally. Provider policies still govern data handling and retention. Do not submit credentials, private keys, personal data, or material you are not allowed to share.

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

Use Add text file to load a source, log, or configuration file up to 256 KiB. Nothing is sent until you click Send. Save the latest answer as a Markdown or text report.

## Safety boundary

Aegis is advisory software, not a penetration-testing engine. It supports scoped, authorized security work and refuses actionable help for credential theft, malware, persistence, evasion, exfiltration, destructive activity, and unauthorized access. It does not initiate external network activity or execute commands.

The complete assistant persona is in [PERSONA.md](PERSONA.md).


