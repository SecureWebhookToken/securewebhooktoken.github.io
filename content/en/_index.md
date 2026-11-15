---
bookFlatSection: true
title: "Secure Webhook Token (SWT) Documentation"
---

# Secure Webhook Token (SWT) Documentation

This documentation describes the IETF Draft specification for Secure Webhook Tokens (SWT) based on [`draft-knauer-secure-webhook-token-03`](https://datatracker.ietf.org/doc/draft-knauer-secure-webhook-token/03/).

Secure Webhook Token (SWT) is a specialized JSON Web Token (JWT) format designed for securely authorizing and verifying webhook requests transmitted via HTTP POST.

## Key Features

- **Standardized**: Based on proven JWT standards (RFC 7519) with specialized `webhook` claims and explicit typing (`typ: "SWT"`)
- **Secure**: Built-in replay protection (`jti`), single-pass body hash verification, cross-service audience validation (`aud`), and algorithm allowlisting
- **Agentic & A2A Ready**: Provides critical defenses against indirect prompt injection, payload poisoning, and unauthorized wakeups in autonomous multi-agent systems
- **Flexible**: Supports empty, structured JSON, and raw request bodies with configurable clock skew leeway
- **Interoperable**: Uses standardized hash algorithm names (SHA-2, SHA-3) and hexadecimal encoding

## Navigation

This documentation is divided into the following sections:

- **Overview and Fundamentals**: Introduction to SWT concepts
- **Specification**: Detailed technical specification
- **Implementation**: Practical implementation examples
- **Security**: Security guidelines and best practices