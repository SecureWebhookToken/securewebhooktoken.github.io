---
weight: 3
bookCollapseSection: false
title: "Replay Protection"
---

## Replay Protection

### In-Memory Replay Protection

```go
package main

import (
    "context"
    "errors"
    "log"
    "net/http"
    "sync"
    "time"

    "github.com/SecureWebhookToken/swt"
)

// MemoryReplayChecker implements replay protection using in-memory storage
type MemoryReplayChecker struct {
    mu    sync.RWMutex
    seen  map[string]time.Time
    ttl   time.Duration
    ticker *time.Ticker
    done   chan struct{}
}

// NewMemoryReplayChecker creates a new in-memory replay checker
func NewMemoryReplayChecker(ttl time.Duration) *MemoryReplayChecker {
    checker := &MemoryReplayChecker{
        seen:   make(map[string]time.Time),
        ttl:    ttl,
        ticker: time.NewTicker(ttl / 2),
        done:   make(chan struct{}),
    }

    // Start cleanup goroutine
    go checker.cleanup()

    return checker
}

// CheckAndRecord implements the swt.ReplayChecker interface
func (m *MemoryReplayChecker) CheckAndRecord(ctx context.Context, jti string) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    // Check if token has been seen before
    if _, exists := m.seen[jti]; exists {
        return errors.New("replay attack detected: token already used")
    }

    // Record the token
    m.seen[jti] = time.Now()
    return nil
}

// cleanup removes expired JTIs
func (m *MemoryReplayChecker) cleanup() {
    for {
        select {
        case <-m.ticker.C:
            m.mu.Lock()
            now := time.Now()
            for jti, timestamp := range m.seen {
                if now.Sub(timestamp) > m.ttl {
                    delete(m.seen, jti)
                }
            }
            m.mu.Unlock()
        case <-m.done:
            m.ticker.Stop()
            return
        }
    }
}

// Close stops the cleanup goroutine
func (m *MemoryReplayChecker) Close() {
    close(m.done)
}

func main() {
    secretKey := []byte("your-secret-key-min-256-bits")

    // Create replay checker with 15 minute TTL
    replayChecker := NewMemoryReplayChecker(15 * time.Minute)
    defer replayChecker.Close()

    // Configure handler with replay protection
    opts := &swt.HandlerOptions{
        MaxBodySize:   5 * 1024 * 1024,
        ReplayChecker: replayChecker,
    }

    webhookHandler := swt.NewHandlerFunc(secretKey, handleWebhook, opts)

    http.HandleFunc("/webhook", webhookHandler)

    log.Println("Webhook server with replay protection on :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal(err)
    }
}

func handleWebhook(token *swt.SecureWebhookToken, body []byte) error {
    log.Printf("Processing webhook: %s (jti: %s)", token.Webhook().Event, token.ID())
    return nil
}
```

### Redis-based Replay Protection

```go
package main

import (
    "context"
    "errors"
    "fmt"
    "log"
    "net/http"
    "time"

    "github.com/SecureWebhookToken/swt"
    "github.com/redis/go-redis/v9"
)

// RedisReplayChecker implements replay protection using Redis
type RedisReplayChecker struct {
    client *redis.Client
    ttl    time.Duration
}

// NewRedisReplayChecker creates a new Redis-based replay checker
func NewRedisReplayChecker(addr string, ttl time.Duration) *RedisReplayChecker {
    client := redis.NewClient(&redis.Options{
        Addr:     addr,
        Password: "", // Set if needed
        DB:       0,
    })

    return &RedisReplayChecker{
        client: client,
        ttl:    ttl,
    }
}

// CheckAndRecord implements the swt.ReplayChecker interface
func (r *RedisReplayChecker) CheckAndRecord(ctx context.Context, jti string) error {
    key := fmt.Sprintf("swt:jti:%s", jti)

    // Try to set the key only if it doesn't exist (NX flag)
    result, err := r.client.SetNX(ctx, key, "1", r.ttl).Result()
    if err != nil {
        return fmt.Errorf("redis error: %w", err)
    }

    if !result {
        return errors.New("replay attack detected: token already used")
    }

    return nil
}

// Close closes the Redis connection
func (r *RedisReplayChecker) Close() error {
    return r.client.Close()
}

func main() {
    secretKey := []byte("your-secret-key-min-256-bits")

    // Create Redis replay checker
    replayChecker := NewRedisReplayChecker("localhost:6379", 15*time.Minute)
    defer replayChecker.Close()

    // Test Redis connection
    ctx := context.Background()
    if err := replayChecker.client.Ping(ctx).Err(); err != nil {
        log.Fatalf("Redis connection failed: %v", err)
    }

    opts := &swt.HandlerOptions{
        MaxBodySize:   5 * 1024 * 1024,
        ReplayChecker: replayChecker,
    }

    webhookHandler := swt.NewHandlerFunc(secretKey, handleWebhook, opts)

    http.HandleFunc("/webhook", webhookHandler)

    log.Println("Webhook server with Redis replay protection on :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal(err)
    }
}

func handleWebhook(token *swt.SecureWebhookToken, body []byte) error {
    log.Printf("Processing webhook: %s (jti: %s)", token.Webhook().Event, token.ID())
    return nil
}
```

### Database-based Replay Protection (PostgreSQL)

```go
package main

import (
    "context"
    "database/sql"
    "errors"
    "log"
    "net/http"
    "time"

    "github.com/SecureWebhookToken/swt"
    _ "github.com/lib/pq"
)

// PostgresReplayChecker implements replay protection using PostgreSQL
type PostgresReplayChecker struct {
    db  *sql.DB
    ttl time.Duration
}

// NewPostgresReplayChecker creates a new PostgreSQL-based replay checker
func NewPostgresReplayChecker(connStr string, ttl time.Duration) (*PostgresReplayChecker, error) {
    db, err := sql.Open("postgres", connStr)
    if err != nil {
        return nil, err
    }

    // Create table if it doesn't exist
    _, err = db.Exec(`
        CREATE TABLE IF NOT EXISTS webhook_tokens (
            jti VARCHAR(255) PRIMARY KEY,
            created_at TIMESTAMP NOT NULL DEFAULT NOW(),
            expires_at TIMESTAMP NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_expires_at ON webhook_tokens(expires_at);
    `)
    if err != nil {
        return nil, err
    }

    checker := &PostgresReplayChecker{
        db:  db,
        ttl: ttl,
    }

    // Start cleanup goroutine
    go checker.cleanupExpired()

    return checker, nil
}

// CheckAndRecord implements the swt.ReplayChecker interface
func (p *PostgresReplayChecker) CheckAndRecord(ctx context.Context, jti string) error {
    expiresAt := time.Now().Add(p.ttl)

    // Try to insert the JTI
    _, err := p.db.ExecContext(ctx, `
        INSERT INTO webhook_tokens (jti, expires_at)
        VALUES ($1, $2)
    `, jti, expiresAt)

    if err != nil {
        // Check if it's a duplicate key error
        if isDuplicateKeyError(err) {
            return errors.New("replay attack detected: token already used")
        }
        return fmt.Errorf("database error: %w", err)
    }

    return nil
}

// cleanupExpired removes expired tokens periodically
func (p *PostgresReplayChecker) cleanupExpired() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()

    for range ticker.C {
        _, err := p.db.Exec(`
            DELETE FROM webhook_tokens
            WHERE expires_at < NOW()
        `)
        if err != nil {
            log.Printf("Failed to cleanup expired tokens: %v", err)
        }
    }
}

// Close closes the database connection
func (p *PostgresReplayChecker) Close() error {
    return p.db.Close()
}

func isDuplicateKeyError(err error) bool {
    // PostgreSQL duplicate key error code: 23505
    return err != nil && (err.Error() == "pq: duplicate key value violates unique constraint \"webhook_tokens_pkey\"" ||
        strings.Contains(err.Error(), "23505"))
}

func main() {
    secretKey := []byte("your-secret-key-min-256-bits")

    // Database connection string
    connStr := "postgres://user:password@localhost/webhooks?sslmode=disable"

    // Create PostgreSQL replay checker
    replayChecker, err := NewPostgresReplayChecker(connStr, 15*time.Minute)
    if err != nil {
        log.Fatalf("Failed to create replay checker: %v", err)
    }
    defer replayChecker.Close()

    opts := &swt.HandlerOptions{
        MaxBodySize:   5 * 1024 * 1024,
        ReplayChecker: replayChecker,
    }

    webhookHandler := swt.NewHandlerFunc(secretKey, handleWebhook, opts)

    http.HandleFunc("/webhook", webhookHandler)

    log.Println("Webhook server with PostgreSQL replay protection on :8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal(err)
    }
}

func handleWebhook(token *swt.SecureWebhookToken, body []byte) error {
    log.Printf("Processing webhook: %s (jti: %s)", token.Webhook().Event, token.ID())
    return nil
}
```

### Testing Replay Protection

```go
package main

import (
    "bytes"
    "context"
    "fmt"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/SecureWebhookToken/swt"
)

func TestReplayProtection(t *testing.T) {
    secretKey := []byte("test-secret-key-for-testing-only")

    // Create replay checker
    replayChecker := NewMemoryReplayChecker(5 * time.Minute)
    defer replayChecker.Close()

    // Create handler with replay protection
    opts := &swt.HandlerOptions{
        ReplayChecker: replayChecker,
    }

    webhookHandler := swt.NewHandlerFunc(secretKey, func(token *swt.SecureWebhookToken, body []byte) error {
        return nil
    }, opts)

    // Create test server
    server := httptest.NewServer(webhookHandler)
    defer server.Close()

    // Create webhook request
    req := &swt.Request{
        URL:    server.URL,
        Issuer: "test-service",
        Event:  "test.event",
        Data:   []byte(`{"test":"data"}`),
    }

    // Build HTTP request
    httpReq, err := req.Build(secretKey)
    if err != nil {
        t.Fatalf("Failed to build request: %v", err)
    }

    // First request should succeed
    client := &http.Client{}
    resp, err := client.Do(httpReq)
    if err != nil {
        t.Fatalf("First request failed: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        t.Errorf("Expected status 200, got %d", resp.StatusCode)
    }

    // Second request with same token should fail (replay attack)
    // Recreate the request with the same body
    httpReq2, err := http.NewRequest("POST", server.URL, bytes.NewReader(httpReq.Body))
    if err != nil {
        t.Fatalf("Failed to create second request: %v", err)
    }
    httpReq2.Header = httpReq.Header

    resp2, err := client.Do(httpReq2)
    if err != nil {
        t.Fatalf("Second request failed: %v", err)
    }
    defer resp2.Body.Close()

    if resp2.StatusCode != http.StatusUnauthorized {
        t.Errorf("Expected status 401 for replay attack, got %d", resp2.StatusCode)
    }

    fmt.Println("Replay protection test passed!")
}
```
