---
bookFlatSection: true
title: "Secure Webhook Token (SWT) Documentation"
---

# Secure Webhook Token (SWT) Documentation

This documentation describes the IETF Draft specification for Secure Webhook Tokens (SWT) based on [`draft-knauer-secure-webhook-token-01`](https://datatracker.ietf.org/doc/draft-knauer-secure-webhook-token/01/).

Secure Webhook Token (SWT) is a specialized JSON Web Token (JWT) format designed for securely authorizing and verifying webhook requests transmitted via HTTP POST.

## Key Features

- **Standardized**: Based on proven JWT standards with specialized webhook claims
- **Secure**: Built-in replay protection, hash validation, and algorithm allowlisting
- **Flexible**: Supports both empty and non-empty request bodies
- **Interoperable**: Uses standardized hash algorithm names and hexadecimal encoding

## Navigation

This documentation is divided into the following sections:

- **Overview and Fundamentals**: Introduction to SWT concepts
- **Specification**: Detailed technical specification
- **Implementation**: Practical implementation examples
- **Security**: Security guidelines and best practices