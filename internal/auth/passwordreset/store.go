package passwordreset

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/database/dbgen"
)

type Token struct {
	ID        int64
	UserID    int64
	ExpiresAt time.Time
	UsedAt    *string
	Value     string
}

type Store struct {
	database *sql.DB
	queries  *dbgen.Queries
	now      func() time.Time
}

func NewStore(database *sql.DB) *Store {
	return &Store{database: database, queries: dbgen.New(database), now: time.Now}
}

func (store *Store) Create(ctx context.Context, userID int64) (Token, error) {
	now := store.now().UTC()
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		return Token{}, fmt.Errorf("generate password reset token: %w", err)
	}
	value := hex.EncodeToString(tokenBytes)
	expiresAt := now.Add(15 * time.Minute)
	if err := store.queries.CreatePasswordResetToken(ctx, dbgen.CreatePasswordResetTokenParams{
		UserID: userID, TokenHash: hashToken(value), ExpiresAt: formatTimestamp(expiresAt),
	}); err != nil {
		return Token{}, fmt.Errorf("create password reset token: %w", err)
	}
	return Token{UserID: userID, ExpiresAt: expiresAt, Value: value}, nil
}

func (store *Store) Validate(ctx context.Context, value string) (Token, bool, error) {
	row, err := store.queries.GetPasswordResetToken(ctx, hashToken(value))
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, false, nil
	}
	if err != nil {
		return Token{}, false, fmt.Errorf("find password reset token: %w", err)
	}
	expiresAt, err := time.Parse(time.RFC3339, row.ExpiresAt)
	if err != nil || !store.now().Before(expiresAt) || row.UsedAt != nil {
		return Token{}, false, nil
	}
	return Token{ID: row.ID, UserID: row.UserID, ExpiresAt: expiresAt, UsedAt: row.UsedAt, Value: value}, true, nil
}

func (store *Store) ResetPassword(ctx context.Context, value, passwordHash string) (bool, error) {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin password reset: %w", err)
	}
	// Rollback aborts on error or early return. After Commit it is a no-op (sql.ErrTxDone).
	defer transaction.Rollback()

	/*
	   defer transaction.Rollback() is a safety net.

	   If everything succeeds, Commit() runs and permanently saves
	   the transaction. Later, the deferred Rollback() still runs,
	   but the transaction is already finished, so database/sql
	   returns sql.ErrTxDone and nothing is undone.

	   ErrTxDone( transaction has already been committed or rolled back, so it can't be used anymore.)

	   If anything fails or the function returns early before Commit(),
	   the deferred Rollback() aborts the transaction automatically.

	   That's why Rollback() is deferred at the top:
	   every failure path is covered automatically, and the changes
	   are kept only when all steps succeed and Commit() is called.
	*/

	queries := store.queries.WithTx(transaction)
	now := formatTimestamp(store.now().UTC())
	userID, err := queries.ConsumePasswordResetToken(ctx, dbgen.ConsumePasswordResetTokenParams{
		Now:       &now,
		TokenHash: hashToken(value),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("consume password reset token: %w", err)
	}
	result, err := queries.ResetUserPasswordHash(ctx, dbgen.ResetUserPasswordHashParams{
		PasswordHash: passwordHash, Now: now, UserID: userID,
	})
	if err != nil {
		return false, fmt.Errorf("reset user password: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read password reset: %w", err)
	}
	if rowsAffected != 1 {
		return false, nil
	}
	if err := queries.ConsumeRemainingPasswordResetTokens(ctx, dbgen.ConsumeRemainingPasswordResetTokensParams{
		Now:    &now,
		UserID: userID,
	}); err != nil {
		return false, fmt.Errorf("invalidate remaining password reset tokens: %w", err)
	}
	if err := queries.RevokeUserSessions(ctx, dbgen.RevokeUserSessionsParams{
		Now:    &now,
		UserID: userID,
	}); err != nil {
		return false, fmt.Errorf("revoke user sessions: %w", err)
	}
	if err := queries.DeleteTOTPLoginChallengesForUser(ctx, userID); err != nil {
		return false, fmt.Errorf("delete TOTP login challenges: %w", err)
	}
	if err := transaction.Commit(); err != nil { //transaction committed
		return false, fmt.Errorf("commit password reset: %w", err)
	}
	return true, nil
}

func hashToken(token string) string {
	tokenHash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(tokenHash[:]) // array -> slice -> hex string
}

func formatTimestamp(timestamp time.Time) string {
	return timestamp.UTC().Format("2006-01-02T15:04:05.000Z")
}
