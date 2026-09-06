package store

import (
	"crypto/rand"
	"encoding/hex"
)

// newID returns a random 16-byte hex-encoded id, used for every primary key
// in this schema. Postgres-generated UUIDs would need the pgcrypto/uuid-ossp
// extension enabled on whatever instance a customer points this at;
// app-generated ids keep the schema itself dependency-free.
func newID(prefix string) string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	return prefix + "_" + hex.EncodeToString(buf)
}
