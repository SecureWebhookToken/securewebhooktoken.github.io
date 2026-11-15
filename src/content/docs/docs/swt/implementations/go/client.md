---
title: "Go: Client-side Token Generation"
description: "Generate and sign Secure Webhook Tokens in Go using github.com/SecureWebhookToken/swt v0.5.0, including empty bodies, options, and retry logic."
---

## Client-side Token Generation

### Installation

```bash
go get github.com/SecureWebhookToken/swt@v0.5.0
```

### Basic Token Creation and Sending

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

    // Create a webhook request with payload and audience targeting
    req := &swt.Request{
        URL:      "https://api.example.com/webhook",
        Issuer:   "https://auth.example.com",
        Audience: "https://api.example.com/webhook",
        Event:    "user.created",
        HashAlg:  swt.SHA256, // Optional: defaults to SHA-256
        Data:     []byte(`{"userId":"12345","email":"user@example.com"}`),
    }

    // Build the HTTP request with embedded SWT token
    httpReq, err := req.Build(secretKey)
    if err != nil {
        log.Fatalf("Failed to build request: %v", err)
    }

    // Send the request
    client := &http.Client{}
    resp, err := client.Do(httpReq)
    if err != nil {
        log.Fatalf("Failed to send request: %v", err)
    }
    defer resp.Body.Close()

    fmt.Printf("Response status: %s\n", resp.Status)
}
```

### Token Creation with Empty Body

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

    // Create a webhook request without payload (empty body)
    req := &swt.Request{
        URL:    "https://api.example.com/webhook",
        Issuer: "webhook-service.example.com",
        Event:  "health.check",
        Data:   nil, // No payload
    }

    httpReq, err := req.Build(secretKey)
    if err != nil {
        log.Fatalf("Failed to build request: %v", err)
    }

    client := &http.Client{}
    resp, err := client.Do(httpReq)
    if err != nil {
        log.Fatalf("Failed to send request: %v", err)
    }
    defer resp.Body.Close()

    fmt.Printf("Health check response: %s\n", resp.Status)
}
```

### Advanced Token Creation with Options

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

    // Create token with custom options
    req := &swt.Request{
        URL:     "https://api.example.com/webhook",
        Issuer:  "webhook-service.example.com",
        Event:   "payment.received",
        HashAlg: swt.SHA384, // Use SHA-384 instead of default SHA-256
        Data:    []byte(`{"amount":100.00,"currency":"USD"}`),
    }

    // Build with custom options
    ctx := context.Background()
    httpReq, err := req.BuildWithContext(ctx, secretKey,
        swt.WithID(uuid.New().String()),              // Custom JWT ID
        swt.WithSubject("user-12345"),                // Subject identifier
        swt.WithExpiresAt(time.Now().Add(5*time.Minute)), // 5 minute expiry
        swt.WithNotBefore(time.Now()),                // Valid immediately
        swt.WithRetryCount(0),                        // First delivery attempt
    )
    if err != nil {
        log.Fatalf("Failed to build request: %v", err)
    }

    client := &http.Client{}
    resp, err := client.Do(httpReq)
    if err != nil {
        log.Fatalf("Failed to send request: %v", err)
    }
    defer resp.Body.Close()

    fmt.Printf("Payment webhook sent: %s\n", resp.Status)
}
```

### Creating Token Manually (Low-level API)

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

    // Create hash for the payload
    payload := []byte(`{"userId":"12345"}`)
    hash, err := swt.NewHash(swt.SHA256, payload)
    if err != nil {
        log.Fatalf("Failed to create payload hash: %v", err)
    }

    // Create token with event and hash
    token, err := swt.New(
        "webhook-service.example.com", // issuer
        "user.created",                 // event
        hash,                           // payload hash
        swt.WithID(uuid.New().String()),
        swt.WithExpiresAt(time.Now().Add(5*time.Minute)),
        swt.WithNotBefore(time.Now()),
        swt.WithSubject("user-12345"),
    )
    if err != nil {
        log.Fatalf("Failed to create token: %v", err)
    }

    // Sign the token
    tokenString, err := token.SignedString(secretKey)
    if err != nil {
        log.Fatalf("Failed to sign token: %v", err)
    }

    fmt.Printf("Token: %s\n", tokenString)
    fmt.Printf("Event: %s\n", token.Webhook().Event)
    fmt.Printf("Hash: %s\n", token.Webhook().Hash.String())
}
```

### Retry Logic with Retry Count

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
        // Build request with current retry count
        httpReq, err := req.Build(secretKey, swt.WithRetryCount(retry))
        if err != nil {
            return fmt.Errorf("failed to build request: %w", err)
        }

        resp, err := client.Do(httpReq)
        if err != nil {
            log.Printf("Attempt %d failed: %v", retry, err)
            if retry < maxRetries {
                time.Sleep(time.Duration(retry+1) * 2 * time.Second) // Exponential backoff
                continue
            }
            return fmt.Errorf("all retry attempts failed: %w", err)
        }
        defer resp.Body.Close()

        if resp.StatusCode >= 200 && resp.StatusCode < 300 {
            fmt.Printf("Webhook delivered successfully on attempt %d\n", retry)
            return nil
        }

        log.Printf("Attempt %d returned status %d", retry, resp.StatusCode)
        if retry < maxRetries {
            time.Sleep(time.Duration(retry+1) * 2 * time.Second)
        }
    }

    return fmt.Errorf("webhook delivery failed after %d attempts", maxRetries)
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
        log.Fatalf("Webhook delivery failed: %v", err)
    }
}
```