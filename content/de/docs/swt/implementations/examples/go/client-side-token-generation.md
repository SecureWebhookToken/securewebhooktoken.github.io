---
weight: 1
bookCollapseSection: false
title: "Client-seitige Token-Generierung"
---

## Client-seitige Token-Generierung

### Installation

```bash
go get github.com/SecureWebhookToken/swt@v0.4.0
```

### Grundlegende Token-Erstellung und -Versand

```go
package main

import (
    "fmt"
    "log"
    "net/http"

    "github.com/SecureWebhookToken/swt"
)

func main() {
    secretKey := []byte("your-secret-key-min-256-bits")

    // Webhook-Request mit Payload und Zielgruppen-Targeting (Audience) erstellen
    req := &swt.Request{
        URL:      "https://api.example.com/webhook",
        Issuer:   "https://auth.example.com",
        Audience: "https://api.example.com/webhook",
        Event:    "user.created",
        HashAlg:  swt.SHA256, // Optional: Standard ist SHA-256
        Data:     []byte(`{"userId":"12345","email":"user@example.com"}`),
    }

    // HTTP-Request mit eingebettetem SWT-Token erstellen
    httpReq, err := req.Build(secretKey)
    if err != nil {
        log.Fatalf("Request-Erstellung fehlgeschlagen: %v", err)
    }

    // Request senden
    client := &http.Client{}
    resp, err := client.Do(httpReq)
    if err != nil {
        log.Fatalf("Request-Versand fehlgeschlagen: %v", err)
    }
    defer resp.Body.Close()

    fmt.Printf("Response-Status: %s\n", resp.Status)
}
```

### Token-Erstellung mit leerem Body

```go
package main

import (
    "fmt"
    "log"
    "net/http"

    "github.com/SecureWebhookToken/swt"
)

func main() {
    secretKey := []byte("your-secret-key-min-256-bits")

    // Webhook-Request ohne Payload erstellen (leerer Body)
    req := &swt.Request{
        URL:    "https://api.example.com/webhook",
        Issuer: "webhook-service.example.com",
        Event:  "health.check",
        Data:   nil, // Keine Payload
    }

    httpReq, err := req.Build(secretKey)
    if err != nil {
        log.Fatalf("Request-Erstellung fehlgeschlagen: %v", err)
    }

    client := &http.Client{}
    resp, err := client.Do(httpReq)
    if err != nil {
        log.Fatalf("Request-Versand fehlgeschlagen: %v", err)
    }
    defer resp.Body.Close()

    fmt.Printf("Health-Check-Response: %s\n", resp.Status)
}
```

### Erweiterte Token-Erstellung mit Optionen

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    "github.com/SecureWebhookToken/swt"
    "github.com/google/uuid"
)

func main() {
    secretKey := []byte("your-secret-key-min-256-bits")

    // Token mit benutzerdefinierten Optionen erstellen
    req := &swt.Request{
        URL:     "https://api.example.com/webhook",
        Issuer:  "webhook-service.example.com",
        Event:   "payment.received",
        HashAlg: swt.SHA384, // SHA-384 statt Standard SHA-256 verwenden
        Data:    []byte(`{"amount":100.00,"currency":"USD"}`),
    }

    // Mit benutzerdefinierten Optionen erstellen
    ctx := context.Background()
    httpReq, err := req.BuildWithContext(ctx, secretKey,
        swt.WithID(uuid.New().String()),              // Benutzerdefinierte JWT-ID
        swt.WithSubject("user-12345"),                // Subject-Identifikator
        swt.WithExpiresAt(time.Now().Add(5*time.Minute)), // 5 Minuten Gültigkeit
        swt.WithNotBefore(time.Now()),                // Sofort gültig
        swt.WithRetryCount(0),                        // Erster Zustellungsversuch
    )
    if err != nil {
        log.Fatalf("Request-Erstellung fehlgeschlagen: %v", err)
    }

    client := &http.Client{}
    resp, err := client.Do(httpReq)
    if err != nil {
        log.Fatalf("Request-Versand fehlgeschlagen: %v", err)
    }
    defer resp.Body.Close()

    fmt.Printf("Payment-Webhook gesendet: %s\n", resp.Status)
}
```

### Token manuell erstellen (Low-level API)

```go
package main

import (
    "fmt"
    "log"
    "time"

    "github.com/SecureWebhookToken/swt"
    "github.com/google/uuid"
)

func main() {
    secretKey := []byte("your-secret-key-min-256-bits")

    // Hash für die Payload erstellen
    payload := []byte(`{"userId":"12345"}`)
    hash := swt.NewHash(swt.SHA256, payload)

    // Token mit Event und Hash erstellen
    token, err := swt.New(
        "webhook-service.example.com", // Issuer
        "user.created",                 // Event
        hash,                           // Payload-Hash
        swt.WithID(uuid.New().String()),
        swt.WithExpiresAt(time.Now().Add(5*time.Minute)),
        swt.WithNotBefore(time.Now()),
        swt.WithSubject("user-12345"),
    )
    if err != nil {
        log.Fatalf("Token-Erstellung fehlgeschlagen: %v", err)
    }

    // Token signieren
    tokenString, err := token.SignedString(secretKey)
    if err != nil {
        log.Fatalf("Token-Signierung fehlgeschlagen: %v", err)
    }

    fmt.Printf("Token: %s\n", tokenString)
    fmt.Printf("Event: %s\n", token.Webhook().Event)
    fmt.Printf("Hash: %s\n", token.Webhook().Hash.String())
}
```

### Retry-Logik mit Retry-Count

```go
package main

import (
    "fmt"
    "log"
    "net/http"
    "time"

    "github.com/SecureWebhookToken/swt"
)

func sendWebhookWithRetry(req *swt.Request, secretKey []byte, maxRetries uint) error {
    client := &http.Client{Timeout: 30 * time.Second}

    for retry := uint(0); retry <= maxRetries; retry++ {
        // Request mit aktuellem Retry-Count erstellen
        httpReq, err := req.Build(secretKey, swt.WithRetryCount(retry))
        if err != nil {
            return fmt.Errorf("Request-Erstellung fehlgeschlagen: %w", err)
        }

        resp, err := client.Do(httpReq)
        if err != nil {
            log.Printf("Versuch %d fehlgeschlagen: %v", retry, err)
            if retry < maxRetries {
                time.Sleep(time.Duration(retry+1) * 2 * time.Second) // Exponentieller Backoff
                continue
            }
            return fmt.Errorf("alle Wiederholungsversuche fehlgeschlagen: %w", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode >= 200 && resp.StatusCode < 300 {
            fmt.Printf("Webhook erfolgreich zugestellt bei Versuch %d\n", retry)
            return nil
        }

        log.Printf("Versuch %d ergab Status %d", retry, resp.StatusCode)
        if retry < maxRetries {
            time.Sleep(time.Duration(retry+1) * 2 * time.Second)
        }
    }

    return fmt.Errorf("Webhook-Zustellung fehlgeschlagen nach %d Versuchen", maxRetries)
}

func main() {
    secretKey := []byte("your-secret-key-min-256-bits")

    req := &swt.Request{
        URL:    "https://api.example.com/webhook",
        Issuer: "webhook-service.example.com",
        Event:  "order.completed",
        Data:   []byte(`{"orderId":"ORD-12345","total":250.00}`),
    }

    if err := sendWebhookWithRetry(req, secretKey, 3); err != nil {
        log.Fatalf("Webhook-Zustellung fehlgeschlagen: %v", err)
    }
}
```