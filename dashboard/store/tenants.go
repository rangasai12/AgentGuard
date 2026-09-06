package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

var ErrNotFound = errors.New("not found")
var ErrEmailTaken = errors.New("email already registered")
var ErrInvalidCredentials = errors.New("invalid email or password")

// SignUp creates a new tenant, a new user as its sole admin, and a
// membership linking them, all in one transaction — the self-serve
// "a company signs up" entry point for this hosted SaaS. Returns the new
// user and tenant ids.
func (s *Store) SignUp(ctx context.Context, companyName, email, password string) (userID, tenantID string, err error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("hashing password: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", "", fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)`, email).Scan(&exists); err != nil {
		return "", "", fmt.Errorf("checking existing email: %w", err)
	}
	if exists {
		return "", "", ErrEmailTaken
	}

	userID = newID("user")
	tenantID = newID("tenant")

	if _, err := tx.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1, $2)`, tenantID, companyName); err != nil {
		return "", "", fmt.Errorf("creating tenant: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3)`, userID, email, string(hash)); err != nil {
		return "", "", fmt.Errorf("creating user: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO memberships (user_id, tenant_id, role) VALUES ($1, $2, $3)`, userID, tenantID, RoleAdmin); err != nil {
		return "", "", fmt.Errorf("creating membership: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return "", "", fmt.Errorf("committing signup: %w", err)
	}
	return userID, tenantID, nil
}

// VerifyLogin checks email/password and returns the user id on success.
func (s *Store) VerifyLogin(ctx context.Context, email, password string) (userID string, err error) {
	var hash string
	err = s.pool.QueryRow(ctx, `SELECT id, password_hash FROM users WHERE email = $1`, email).Scan(&userID, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrInvalidCredentials
	}
	if err != nil {
		return "", fmt.Errorf("looking up user: %w", err)
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return "", ErrInvalidCredentials
	}
	return userID, nil
}

// CreateSession issues a new session for userID, valid for ttl, and returns
// the raw session token (only its existence, not the token itself, is
// stored — see hashSecret's doc comment for why that's the right tradeoff
// for a high-entropy secret like this).
func (s *Store) CreateSession(ctx context.Context, userID string, ttl time.Duration) (token string, err error) {
	token = newSecret()
	id := hashSecret(token)
	expiresAt := time.Now().Add(ttl)
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (id, user_id, expires_at) VALUES ($1, $2, $3)`,
		id, userID, expiresAt,
	); err != nil {
		return "", fmt.Errorf("creating session: %w", err)
	}
	return token, nil
}

// UserFromSession resolves a session token to the user it belongs to, or
// ErrNotFound if the token is invalid or expired.
func (s *Store) UserFromSession(ctx context.Context, token string) (User, error) {
	id := hashSecret(token)
	var u User
	err := s.pool.QueryRow(ctx,
		`SELECT users.id, users.email FROM sessions
		 JOIN users ON users.id = sessions.user_id
		 WHERE sessions.id = $1 AND sessions.expires_at > now()`,
		id,
	).Scan(&u.ID, &u.Email)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("looking up session: %w", err)
	}
	return u, nil
}

// DeleteSession invalidates a session token (logout).
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	id := hashSecret(token)
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	return err
}

// Memberships returns every tenant userID belongs to, with their role in
// each — the set of tenants that user is ever allowed to see.
func (s *Store) Memberships(ctx context.Context, userID string) ([]Membership, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT memberships.tenant_id, tenants.name, memberships.role
		 FROM memberships JOIN tenants ON tenants.id = memberships.tenant_id
		 WHERE memberships.user_id = $1 ORDER BY tenants.name`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing memberships: %w", err)
	}
	defer rows.Close()

	var out []Membership
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.TenantID, &m.TenantName, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// MembershipRole returns the caller's role in tenantID, or ErrNotFound if
// they don't belong to it at all. Every webapi handler must call this (or
// rely on a middleware that does) before touching any tenant-scoped data —
// it is the sole gate deciding whether a given user may see a given
// tenant's rows.
func (s *Store) MembershipRole(ctx context.Context, userID, tenantID string) (Role, error) {
	var role Role
	err := s.pool.QueryRow(ctx,
		`SELECT role FROM memberships WHERE user_id = $1 AND tenant_id = $2`,
		userID, tenantID,
	).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("checking membership: %w", err)
	}
	return role, nil
}
