---
bookFlatSection: true
title: "Secure Webhook Token (SWT) Dokumentation"
---

# Secure Webhook Token (SWT) Dokumentation

Diese Dokumentation beschreibt die IETF Draft Spezifikation für Secure Webhook Tokens (SWT) basierend auf [`draft-knauer-secure-webhook-token-01`](https://datatracker.ietf.org/doc/draft-knauer-secure-webhook-token/01/).

Secure Webhook Token (SWT) ist ein spezialisiertes JSON Web Token (JWT)-Format, das für die sichere Autorisierung und Verifizierung von Webhook-Anfragen via HTTP POST entwickelt wurde.

## Hauptfunktionen

- **Standardisiert**: Basiert auf bewährten JWT-Standards mit spezialisierten Webhook-Claims
- **Sicher**: Integrierter Replay-Schutz, Hash-Validierung und Algorithmus-Whitelisting
- **Flexibel**: Unterstützt sowohl leere als auch nicht-leere Request-Bodies
- **Interoperabel**: Verwendet standardisierte Hash-Algorithmusnamen und hexadezimale Kodierung

## Navigation

Diese Dokumentation ist in folgende Bereiche unterteilt:

- **Überblick und Grundlagen**: Einführung in SWT-Konzepte
- **Spezifikation**: Detaillierte technische Spezifikation
- **Implementierung**: Praktische Implementierungsbeispiele
- **Sicherheit**: Sicherheitsrichtlinien und Best Practices