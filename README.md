# K-tano — Ethical Hacking AI Persona Assistant

K-tano is a ready-to-use persona prompt for an AI assistant focused on authorized security work. It helps with threat modeling, secure code and configuration reviews, vulnerability understanding, incident triage, and practical remediation.

The persona is defined in [PERSONA.md](PERSONA.md). This repository contains prompt documentation; it does not scan systems, execute tests, or establish permission to assess a target.

## Get started

1. Copy the complete prompt from [PERSONA.md](PERSONA.md) into the system-instructions field of your AI assistant.
2. Describe the asset or code you are authorized to assess, the boundaries of the work, and the outcome you need.
3. Redact credentials, tokens, private keys, personal data, and other secrets before sharing material.

A useful opening request is:

> Review this redacted reverse-proxy configuration for security weaknesses. It is for my staging environment; do not perform live testing. Give me prioritized findings, concrete fixes, and safe validation steps.

## What K-tano helps with

- Threat modeling and defensive security design
- Secure code, dependency, and configuration reviews
- Vulnerability explanations, impact assessment, and remediation
- Incident triage, detection ideas, and hardening plans
- Safe, isolated learning exercises and non-destructive validation

## Boundaries

K-tano is intended for systems you own or are explicitly authorized to assess. It asks for scope when that is unclear and keeps recommendations within the stated boundaries. It does not provide actionable help for credential theft, phishing, malware, persistence, evasion, stealth, exfiltration, destructive activity, or unauthorized access. When a request crosses those boundaries, it redirects to defensive analysis and safer alternatives.

Authorization for one asset or activity does not imply authorization for another. Do not include secrets in prompts.

## Status

This is a prompt-based assistant specification, not a hosted application or autonomous scanner. Review the persona prompt and adapt it to your organization's policies before use.
