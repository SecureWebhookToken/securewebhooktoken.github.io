---
weight: 2
bookCollapseSection: false
title: "Server-side Validation"
---

## Server-side Validation

### Basic Webhook Handler

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

    // Create webhook handler
    webhookHandler := swt.NewHandlerFunc(
        secretKey,
        handleWebhook,
        nil, // Use default options
    )

    http.HandleFunc("/webhook", webhookHandler)

    log.Println("Webhook server listening on :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal(err)
    }
}

func handleWebhook(token *swt.SecureWebhookToken, body []byte) error {
    webhook := token.Webhook()

    fmt.Printf("Received webhook event: %s\n", webhook.Event)
    fmt.Printf("Issuer: %s\n", token.Issuer())
    fmt.Printf("Token ID: %s\n", token.ID())

    if len(body) > 0 {
        fmt.Printf("Payload: %s\n", string(body))
        fmt.Printf("Hash verified: %s\n", webhook.Hash.String())
    }

    // Process the webhook based on event type
    switch webhook.Event {
    case "user.created":
        return processUserCreated(body)
    case "user.updated":
        return processUserUpdated(body)
    case "payment.received":
        return processPayment(body)
    default:
        log.Printf("Unknown event type: %s", webhook.Event)
    }

    return nil
}

func processUserCreated(body []byte) error {
    fmt.Println("Processing user.created event")
    // Your business logic here
    return nil
}

func processUserUpdated(body []byte) error {
    fmt.Println("Processing user.updated event")
    // Your business logic here
    return nil
}

func processPayment(body []byte) error {
    fmt.Println("Processing payment.received event")
    // Your business logic here
    return nil
}
```

### Handler with Custom Options

```go
package main

import (
    "log"
    "log/slog"
    "net/http"
    "os"

    "github.com/SecureWebhookToken/swt"
)

func main() {
    secretKey := []byte("your-secret-key-min-256-bits")

    // Configure custom logger
    logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelInfo,
    }))

    // Create handler with custom options
    opts := &swt.HandlerOptions{
        MaxBodySize:        10 * 1024 * 1024, // 10MB max body size
        Logger:             logger,
        ReturnErrorDetails: true, // Return detailed errors (use cautiously in production)
    }

    webhookHandler := swt.NewHandlerFunc(secretKey, handleWebhook, opts)

    http.HandleFunc("/webhook", webhookHandler)

    log.Println("Webhook server with custom options listening on :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal(err)
    }
}

func handleWebhook(token *swt.SecureWebhookToken, body []byte) error {
    webhook := token.Webhook()

    slog.Info("Webhook received",
        "event", webhook.Event,
        "issuer", token.Issuer(),
        "jti", token.ID(),
        "retry_count", webhook.RetryCount,
    )

    // Your business logic here

    return nil
}
```

### Manual Token Validation

```go
package main

import (
    "fmt"
    "io"
    "log"
    "net/http"
    "strings"

    "github.com/SecureWebhookToken/swt"
)

func webhookHandler(w http.ResponseWriter, r *http.Request) {
    secretKey := []byte("your-secret-key-min-256-bits")

    // Extract token from Authorization header
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        http.Error(w, "Missing Authorization header", http.StatusUnauthorized)
        return
    }

    tokenString := strings.TrimPrefix(authHeader, "Bearer ")
    if tokenString == authHeader {
        http.Error(w, "Invalid Authorization header format", http.StatusUnauthorized)
        return
    }

    // Read request body
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Failed to read request body", http.StatusBadRequest)
        return
    }
    defer r.Body.Close()

    // Parse and validate the token
    token, err := swt.Parse(tokenString, secretKey)
    if err != nil {
        log.Printf("Token validation failed: %v", err)
        http.Error(w, "Invalid token", http.StatusUnauthorized)
        return
    }

    // Validate the token
    if err := token.Valid(); err != nil {
        log.Printf("Token validation failed: %v", err)
        http.Error(w, "Token validation failed", http.StatusUnauthorized)
        return
    }

    // Verify payload hash if body is present
    webhook := token.Webhook()
    if len(body) > 0 {
        if webhook.Hash == nil {
            http.Error(w, "Missing hash for non-empty body", http.StatusBadRequest)
            return
        }

        // Compute hash of received body
        computedHash := swt.NewHash(webhook.Hash.Algorithm(), body)
        if computedHash.String() != webhook.Hash.String() {
            http.Error(w, "Payload hash mismatch", http.StatusBadRequest)
            return
        }
    } else {
        // Empty body must not have hash
        if webhook.Hash != nil {
            http.Error(w, "Hash must be absent for empty body", http.StatusBadRequest)
            return
        }
    }

    // Process the webhook
    fmt.Printf("Valid webhook received: %s from %s\n", webhook.Event, token.Issuer())

    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"status":"success"}`))
}

func main() {
    http.HandleFunc("/webhook", webhookHandler)

    log.Println("Manual validation webhook server listening on :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal(err)
    }
}
```

### Validation with Custom Claims

```go
package main

import (
    "fmt"
    "log"
    "net/http"

    "github.com/SecureWebhookToken/swt"
    "github.com/golang-jwt/jwt/v5"
)

// CustomClaims extends WebhookClaims with additional fields
type CustomClaims struct {
    swt.WebhookClaims
    TenantID string `json:"tenant_id,omitempty"`
    UserRole string `json:"user_role,omitempty"`
}

func main() {
    secretKey := []byte("your-secret-key-min-256-bits")

    http.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
        tokenString := r.Header.Get("Authorization")
        tokenString = tokenString[len("Bearer "):]

        // Parse with custom claims
        claims := &CustomClaims{}
        token, err := swt.ParseWithClaims(tokenString, claims, secretKey)
        if err != nil {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        // Access custom fields
        fmt.Printf("Event: %s\n", claims.Webhook.Event)
        fmt.Printf("Tenant ID: %s\n", claims.TenantID)
        fmt.Printf("User Role: %s\n", claims.UserRole)

        // Your business logic here

        w.WriteHeader(http.StatusOK)
        w.Write([]byte(`{"status":"success"}`))
    })

    log.Println("Custom claims webhook server listening on :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal(err)
    }
}
```

### Error Handling Best Practices

```go
package main

import (
    "encoding/json"
    "errors"
    "log"
    "net/http"

    "github.com/SecureWebhookToken/swt"
)

type ErrorResponse struct {
    Error   string `json:"error"`
    Message string `json:"message"`
    Code    string `json:"code,omitempty"`
}

func main() {
    secretKey := []byte("your-secret-key-min-256-bits")

    opts := &swt.HandlerOptions{
        MaxBodySize:        5 * 1024 * 1024,
        ReturnErrorDetails: false, // Don't expose internal errors
    }

    webhookHandler := swt.NewHandlerFunc(secretKey, handleWebhookWithErrors, opts)

    http.HandleFunc("/webhook", webhookHandler)

    log.Println("Webhook server with error handling on :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal(err)
    }
}

func handleWebhookWithErrors(token *swt.SecureWebhookToken, body []byte) error {
    webhook := token.Webhook()

    log.Printf("Processing webhook: %s (jti: %s)", webhook.Event, token.ID())

    // Simulate different error scenarios
    switch webhook.Event {
    case "user.created":
        // Successful processing
        log.Printf("User created successfully")
        return nil

    case "payment.failed":
        // Business logic error
        return &WebhookError{
            Code:    "PAYMENT_PROCESSING_ERROR",
            Message: "Payment processing failed",
            Status:  http.StatusUnprocessableEntity,
        }

    case "invalid.event":
        // Unknown event type
        return &WebhookError{
            Code:    "UNKNOWN_EVENT",
            Message: "Event type not supported",
            Status:  http.StatusBadRequest,
        }

    default:
        log.Printf("Processing event: %s", webhook.Event)
        return nil
    }
}

// WebhookError represents a structured webhook processing error
type WebhookError struct {
    Code    string
    Message string
    Status  int
}

func (e *WebhookError) Error() string {
    return e.Message
}

// Custom error handler wrapper
func customWebhookHandler(secretKey []byte) http.HandlerFunc {
    baseHandler := swt.NewHandlerFunc(secretKey, handleWebhookWithErrors, nil)

    return func(w http.ResponseWriter, r *http.Request) {
        // Create a custom response writer to capture status
        baseHandler(w, r)

        // Additional logging or monitoring can be added here
    }
}
```
