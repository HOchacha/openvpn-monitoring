package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Block is a temporary bar on a user connecting.
//
// It is not a revocation. The certificate stays valid, and the block lifts on
// its own - which is the whole point of having it as a separate thing.
type Block struct {
	CommonName string    `json:"common_name"`
	Until      time.Time `json:"-"` // zero means indefinite; see MarshalJSON
	Reason     string    `json:"reason,omitempty"`
	CreatedBy  string    `json:"created_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// MarshalJSON omits a zero expiry rather than writing year 1.
//
// encoding/json's omitempty does nothing for a struct, so an indefinite block
// would serialise as "0001-01-01T00:00:00Z" - a date in the past, which any
// consumer comparing it against now would read as already expired.
func (b Block) MarshalJSON() ([]byte, error) {
	type alias Block // avoids recursing back into this method
	out := struct {
		alias
		Until *time.Time `json:"until,omitempty"`
	}{alias: alias(b)}
	if !b.Until.IsZero() {
		t := b.Until
		out.Until = &t
	}
	return json.Marshal(out)
}

// UnmarshalJSON is the counterpart to MarshalJSON: the tag on Until is "-",
// so without this the expiry would silently decode as zero - turning every
// block that crosses a JSON boundary into an indefinite one.
func (b *Block) UnmarshalJSON(data []byte) error {
	type alias Block
	in := struct {
		*alias
		Until *time.Time `json:"until"`
	}{alias: (*alias)(b)}
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	if in.Until != nil {
		b.Until = *in.Until
	} else {
		b.Until = time.Time{}
	}
	return nil
}

// Indefinite reports whether the block has no expiry.
func (b Block) Indefinite() bool { return b.Until.IsZero() }

// Expired reports whether the block has run out as of now.
func (b Block) Expired(now time.Time) bool {
	return !b.Indefinite() && !now.Before(b.Until)
}

// SetBlock records a block, replacing any existing one for the same user.
func (s *Store) SetBlock(ctx context.Context, b Block) error {
	if b.CreatedAt.IsZero() {
		b.CreatedAt = time.Now()
	}

	// An expiry of zero is stored as zero and read back as "indefinite", so
	// the two cases stay distinguishable without a nullable column.
	var until int64
	if !b.Until.IsZero() {
		until = b.Until.Unix()
	}

	const sqliteQ = `INSERT INTO user_blocks
		(common_name, until, reason, created_by, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (common_name) DO UPDATE SET
			until = excluded.until, reason = excluded.reason,
			created_by = excluded.created_by, created_at = excluded.created_at`
	const mysqlQ = `INSERT INTO user_blocks
		(common_name, until, reason, created_by, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			until = VALUES(until), reason = VALUES(reason),
			created_by = VALUES(created_by), created_at = VALUES(created_at)`

	q := sqliteQ
	if s.dialect == MySQL {
		q = mysqlQ
	}
	_, err := s.db.ExecContext(ctx, q,
		b.CommonName, until, b.Reason, b.CreatedBy, b.CreatedAt.Unix())
	return err
}

// DeleteBlock lifts a block. Removing one that is not there is not an error:
// the caller wants the user unblocked, and they are.
func (s *Store) DeleteBlock(ctx context.Context, commonName string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM user_blocks WHERE common_name = ?`, commonName)
	return err
}

// Blocks returns every recorded block, expired ones included.
//
// Expiry is not filtered here. The caller reconciles what OpenVPN is enforcing
// against what the database says, and it cannot lift a block it was never told
// about.
func (s *Store) Blocks(ctx context.Context) (map[string]Block, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT common_name, until, reason, created_by, created_at FROM user_blocks`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]Block{}
	for rows.Next() {
		var b Block
		var until, created int64
		if err := rows.Scan(&b.CommonName, &until, &b.Reason, &b.CreatedBy, &created); err != nil {
			return nil, err
		}
		if until > 0 {
			b.Until = time.Unix(until, 0).UTC()
		}
		b.CreatedAt = time.Unix(created, 0).UTC()
		out[b.CommonName] = b
	}
	return out, rows.Err()
}

// GetBlock returns one user's block, if there is one.
func (s *Store) GetBlock(ctx context.Context, commonName string) (Block, bool, error) {
	var b Block
	var until, created int64
	err := s.db.QueryRowContext(ctx,
		`SELECT common_name, until, reason, created_by, created_at
		   FROM user_blocks WHERE common_name = ?`, commonName).
		Scan(&b.CommonName, &until, &b.Reason, &b.CreatedBy, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Block{}, false, nil
	}
	if err != nil {
		return Block{}, false, err
	}
	if until > 0 {
		b.Until = time.Unix(until, 0).UTC()
	}
	b.CreatedAt = time.Unix(created, 0).UTC()
	return b, true, nil
}
