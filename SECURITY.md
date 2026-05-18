# Security Policy

GreyNOC Detector Engine is a defensive, public demo and research project. We take vulnerability reports seriously and appreciate responsible disclosure from researchers, users, and defenders.

## Reporting a Vulnerability

Please do not open a public GitHub issue for suspected security vulnerabilities.

To report a vulnerability, email:

**security@greynoc.com**

If that mailbox is not available, contact the repository owner through the GreyNOC GitHub organization profile and include "Security Report: Detector Engine" in the subject or first line of the message.

## What to Include

Please include as much detail as you can safely share:

- A clear description of the vulnerability or security concern.
- Steps to reproduce the issue.
- Affected files, endpoints, commands, or configurations.
- The potential impact.
- Any proof-of-concept details that are safe and non-destructive.
- Suggested remediation, if known.

Do not include live exploit attempts against third-party systems, stolen credentials, private customer data, or destructive payloads.

## Scope

In scope:

- Vulnerabilities in this repository's source code, API, CLI, packaging, Docker configuration, documentation, and example configuration.
- Hardcoded secrets, unsafe defaults, path traversal issues, authentication or authorization weaknesses, unsafe file handling, dependency risks, or data exposure concerns.
- Issues that could cause the engine to generate unsafe output or mishandle attacker-controlled input.

Out of scope:

- Vulnerabilities in third-party services, feeds, or projects referenced by this repository.
- Denial-of-service testing without prior written permission.
- Social engineering, phishing, physical attacks, or attempts to access accounts you do not own.
- Reports based only on automated scanner output without a clear, reproducible security impact.

## Safe Harbor

We support good-faith security research that avoids harm, respects privacy, and gives us a reasonable opportunity to fix reported issues before public disclosure.

To stay within safe harbor:

- Test only against systems and data you own or are authorized to assess.
- Avoid accessing, modifying, deleting, or exfiltrating data that is not yours.
- Stop testing and report promptly if you encounter sensitive data.
- Do not interrupt service availability or degrade repository infrastructure.

## Response Expectations

We will make a best effort to:

- Acknowledge valid reports promptly.
- Triage and prioritize based on severity and exploitability.
- Keep the reporter informed when practical.
- Credit the reporter if they want recognition and disclosure is appropriate.

## Disclosure

Please give GreyNOC a reasonable remediation window before public disclosure. Coordinated disclosure helps protect users and keeps the project useful for the defensive security community.
