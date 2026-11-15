---
bookFlatSection: true
title: "Secure Webhook Token (SWT) Dokumentation"
---

# Secure Webhook Token (SWT) Dokumentation

Diese Dokumentation beschreibt die IETF Draft Spezifikation für Secure Webhook Tokens (SWT) basierend auf [`draft-knauer-secure-webhook-token-03`](https://datatracker.ietf.org/doc/draft-knauer-secure-webhook-token/03/).

Secure Webhook Token (SWT) ist ein spezialisiertes JSON Web Token (JWT)-Format, das für die sichere Autorisierung und Verifizierung von Webhook-Anfragen via HTTP POST entwickelt wurde.

## Hauptfunktionen

- **Standardisiert**: Basiert auf bewährten JWT-Standards (RFC 7519) mit spezialisierten `webhook`-Claims und explizitem Typing (`typ: "SWT"`)
- **Sicher**: Integrierter Replay-Schutz (`jti`), kryptographische Body-Hash-Validierung, Audience-Schutz (`aud`) gegen Cross-Service-Replay und Algorithmus-Whitelisting
- **Agentic & A2A Ready**: Bietet essenziellen Schutz gegen Indirect Prompt Injection und Payload-Poisoning in autonomen Multi-Agenten-Systemen
- **Flexibel**: Unterstützt leere, strukturierte und unstrukturierte Request-Bodies mit konfigurierbarer Clock-Skew-Toleranz
- **Interoperabel**: Verwendet standardisierte Hash-Algorithmusnamen (SHA-2, SHA-3) und hexadezimale Kodierung

## Navigation

Diese Dokumentation ist in folgende Bereiche unterteilt:

- **Überblick und Grundlagen**: Einführung in SWT-Konzepte
- **Spezifikation**: Detaillierte technische Spezifikation
- **Implementierung**: Praktische Implementierungsbeispiele
- **Sicherheit**: Sicherheitsrichtlinien und Best Practices