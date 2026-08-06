//go:build cgo
// +build cgo

package sql

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

func TestMigrate(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	logger := slog.New(slog.DiscardHandler)

	errCheck := func(err error) bool {
		sqlErr, ok := err.(sqlite3.Error)
		if !ok {
			return false
		}
		return sqlErr.ExtendedCode == sqlite3.ErrConstraintUnique
	}

	var sqliteMigrations []migration
	for _, m := range migrations {
		if m.flavor == nil || m.flavor == &flavorSQLite3 {
			sqliteMigrations = append(sqliteMigrations, m)
		}
	}

	c := &conn{db, &flavorSQLite3, logger, errCheck}
	for _, want := range []int{len(sqliteMigrations), 0} {
		got, err := c.migrate()
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("expected %d migrations, got %d", want, got)
		}
	}
}

func TestMigrateFromV2451(t *testing.T) {
	var sqliteMigrations []migration
	for _, m := range migrations {
		if m.flavor == nil || m.flavor == &flavorSQLite3 {
			sqliteMigrations = append(sqliteMigrations, m)
		}
	}
	baseMigrationCount := len(upstreamV2451SQLiteMigrations)
	if len(sqliteMigrations) != baseMigrationCount+1 {
		t.Fatalf("expected %d SQLite migrations including the custom claims upgrade, got %d", baseMigrationCount+1, len(sqliteMigrations))
	}

	upstreamDB := openSQLiteTestDB(t)
	defer upstreamDB.Close()
	applySQLiteMigrationSet(t, upstreamDB, upstreamV2451SQLiteMigrations)

	currentDB := openSQLiteTestDB(t)
	defer currentDB.Close()
	currentHistoricalMigrations := make([][]string, 0, baseMigrationCount)
	for _, migration := range sqliteMigrations[:baseMigrationCount] {
		currentHistoricalMigrations = append(currentHistoricalMigrations, migration.stmts)
	}
	applySQLiteMigrationSet(t, currentDB, currentHistoricalMigrations)
	if got, want := sqliteSchemaSnapshot(t, currentDB), sqliteSchemaSnapshot(t, upstreamDB); !equalStrings(got, want) {
		t.Fatalf("current historical migrations do not match upstream v2.45.1 schema:\ncurrent: %v\nupstream: %v", got, want)
	}

	logger := slog.New(slog.DiscardHandler)
	errCheck := func(err error) bool {
		sqlErr, ok := err.(sqlite3.Error)
		return ok && sqlErr.ExtendedCode == sqlite3.ErrConstraintUnique
	}
	c := &conn{upstreamDB, &flavorSQLite3, logger, errCheck}
	legacyExpiry := time.Now().UTC().Format("2006-01-02 15:04:05.999999999-07:00")

	if _, err := upstreamDB.Exec(`insert into password (email, hash, username, user_id, preferred_username, groups, name, email_verified) values (?, ?, ?, ?, ?, ?, ?, ?);`,
		"user@example.com", []byte("hash"), "user", "user-id", "user", "[\"existing\"]", "User", true); err != nil {
		t.Fatal(err)
	}
	if _, err := upstreamDB.Exec(`
		insert into auth_request (
			id, client_id, response_types, scopes, redirect_uri, nonce, state,
			force_approval_prompt, logged_in,
			claims_user_id, claims_username, claims_preferred_username,
			claims_email, claims_email_verified, claims_groups,
			connector_id, connector_data, expiry,
			code_challenge, code_challenge_method, hmac_key
		) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		"legacy-auth-request", "client", []byte("[\"code\"]"), []byte("[\"openid\"]"), "cb", "", "", false, false,
		"legacy-user", "legacy", "", "legacy@example.com", false, []byte("[]"), "connector", nil, legacyExpiry, "", "", []byte("legacy-hmac")); err != nil {
		t.Fatal(err)
	}
	if _, err := upstreamDB.Exec(`
		insert into auth_code (
			id, client_id, scopes, nonce, redirect_uri,
			claims_user_id, claims_username, claims_preferred_username,
			claims_email, claims_email_verified, claims_groups,
			connector_id, connector_data, expiry,
			code_challenge, code_challenge_method
		) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		"legacy-auth-code", "client", []byte("[\"openid\"]"), "", "cb",
		"legacy-user", "legacy", "", "legacy@example.com", false, []byte("[]"),
		"connector", nil, legacyExpiry, "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := upstreamDB.Exec(`
		insert into refresh_token (
			id, client_id, scopes, nonce,
			claims_user_id, claims_username, claims_preferred_username,
			claims_email, claims_email_verified, claims_groups,
			connector_id, connector_data, token, obsolete_token, created_at, last_used
		) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
		"legacy-refresh", "client", []byte("[\"openid\"]"), "",
		"legacy-user", "legacy", "", "legacy@example.com", false, []byte("[]"),
		"connector", nil, "legacy-token", "", legacyExpiry, legacyExpiry); err != nil {
		t.Fatal(err)
	}

	if got, err := c.migrate(); err != nil {
		t.Fatal(err)
	} else if got != 1 {
		t.Fatalf("expected one upgrade migration, got %d", got)
	}

	for _, table := range []string{"auth_request", "auth_code", "refresh_token"} {
		var columnCount int
		if err := upstreamDB.QueryRow(`select count(*) from pragma_table_info(?) where name = 'claims_custom';`, table).Scan(&columnCount); err != nil {
			t.Fatal(err)
		}
		if columnCount != 1 {
			t.Fatalf("table %s does not have claims_custom", table)
		}
	}
	var email, groups string
	if err := upstreamDB.QueryRow(`select email, groups from password where email = ?;`, "user@example.com").Scan(&email, &groups); err != nil {
		t.Fatal(err)
	}
	if email != "user@example.com" || groups != `["existing"]` {
		t.Fatalf("existing password data changed: email=%q groups=%q", email, groups)
	}
	for _, row := range []struct {
		table string
		id    string
	}{
		{table: "auth_request", id: "legacy-auth-request"},
		{table: "auth_code", id: "legacy-auth-code"},
		{table: "refresh_token", id: "legacy-refresh"},
	} {
		var userID, email string
		var rawCustomClaims []byte
		query := fmt.Sprintf("select claims_user_id, claims_email, claims_custom from %s where id = ?;", row.table)
		if err := upstreamDB.QueryRow(query, row.id).Scan(&userID, &email, &rawCustomClaims); err != nil {
			t.Fatal(err)
		}
		if userID != "legacy-user" || email != "legacy@example.com" {
			t.Fatalf("existing %s data changed: user_id=%q email=%q", row.table, userID, email)
		}
		var customClaims map[string]json.RawMessage
		if err := json.Unmarshal(rawCustomClaims, &customClaims); err != nil {
			t.Fatalf("decode %s custom claims: %v", row.table, err)
		}
		if len(customClaims) != 0 {
			t.Fatalf("expected legacy %s custom claims to decode as empty, got %v", row.table, customClaims)
		}
	}
}

func openSQLiteTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:?_loc=auto")
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func applySQLiteMigrationSet(t *testing.T, db *sql.DB, migrationSet [][]string) {
	t.Helper()
	if _, err := db.Exec(`create table migrations (num integer not null, at timestamptz not null);`); err != nil {
		t.Fatal(err)
	}
	for migrationIndex, statements := range migrationSet {
		for _, statement := range statements {
			if _, err := db.Exec(statement); err != nil {
				t.Fatalf("applying migration %d: %v", migrationIndex+1, err)
			}
		}
		if _, err := db.Exec(`insert into migrations (num, at) values (?, datetime('now'));`, migrationIndex+1); err != nil {
			t.Fatal(err)
		}
	}
}

func sqliteSchemaSnapshot(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`select name from sqlite_master where type = 'table' and name != 'migrations' order by name;`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var schema []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		columns, err := db.Query(`select name, type, "notnull", coalesce(dflt_value, ''), pk from pragma_table_info(?) order by cid;`, table)
		if err != nil {
			t.Fatal(err)
		}
		for columns.Next() {
			var name, columnType, defaultValue string
			var notNull, primaryKey int
			if err := columns.Scan(&name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
				columns.Close()
				t.Fatal(err)
			}
			schema = append(schema, table+"\x00"+name+"\x00"+columnType+"\x00"+fmt.Sprint(notNull)+"\x00"+defaultValue+"\x00"+fmt.Sprint(primaryKey))
		}
		if err := columns.Err(); err != nil {
			columns.Close()
			t.Fatal(err)
		}
		columns.Close()
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return schema
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

var upstreamV2451SQLiteMigrations = [][]string{
	{
		`create table client (id text not null primary key, secret text not null, redirect_uris bytea not null, trusted_peers bytea not null, public boolean not null, name text not null, logo_url text not null);`,
		`create table auth_request (id text not null primary key, client_id text not null, response_types bytea not null, scopes bytea not null, redirect_uri text not null, nonce text not null, state text not null, force_approval_prompt boolean not null, logged_in boolean not null, claims_user_id text not null, claims_username text not null, claims_email text not null, claims_email_verified boolean not null, claims_groups bytea not null, connector_id text not null, connector_data bytea, expiry timestamptz not null);`,
		`create table auth_code (id text not null primary key, client_id text not null, scopes bytea not null, nonce text not null, redirect_uri text not null, claims_user_id text not null, claims_username text not null, claims_email text not null, claims_email_verified boolean not null, claims_groups bytea not null, connector_id text not null, connector_data bytea, expiry timestamptz not null);`,
		`create table refresh_token (id text not null primary key, client_id text not null, scopes bytea not null, nonce text not null, claims_user_id text not null, claims_username text not null, claims_email text not null, claims_email_verified boolean not null, claims_groups bytea not null, connector_id text not null, connector_data bytea);`,
		`create table password (email text not null primary key, hash bytea not null, username text not null, user_id text not null);`,
		`create table keys (id text not null primary key, verification_keys bytea not null, signing_key bytea not null, signing_key_pub bytea not null, next_rotation timestamptz not null);`,
	},
	{
		`alter table refresh_token add column token text not null default '';`,
		`alter table refresh_token add column created_at timestamptz not null default '0001-01-01 00:00:00 UTC';`,
		`alter table refresh_token add column last_used timestamptz not null default '0001-01-01 00:00:00 UTC';`,
	},
	{`create table offline_session (user_id text not null, conn_id text not null, refresh bytea not null, primary key (user_id, conn_id));`},
	{`create table connector (id text not null primary key, type text not null, name text not null, resource_version text not null, config bytea);`},
	{
		`alter table auth_code add column claims_preferred_username text not null default '';`,
		`alter table auth_request add column claims_preferred_username text not null default '';`,
		`alter table refresh_token add column claims_preferred_username text not null default '';`,
	},
	{`alter table offline_session add column connector_data bytea;`},
	{
		`create table device_request (user_code text not null primary key, device_code text not null, client_id text not null, client_secret text, scopes bytea not null, expiry timestamptz not null);`,
		`create table device_token (device_code text not null primary key, status text not null, token bytea, expiry timestamptz not null, last_request timestamptz not null, poll_interval integer not null);`,
	},
	{
		`alter table auth_request add column code_challenge text not null default '';`,
		`alter table auth_request add column code_challenge_method text not null default '';`,
		`alter table auth_code add column code_challenge text not null default '';`,
		`alter table auth_code add column code_challenge_method text not null default '';`,
	},
	{`alter table refresh_token add column obsolete_token text default '';`},
	{
		`alter table device_token add column code_challenge text not null default '';`,
		`alter table device_token add column code_challenge_method text not null default '';`,
	},
	{`alter table auth_request add column hmac_key bytea;`},
	{
		`alter table password add column preferred_username text not null default '';`,
		`alter table password add column groups bytea not null default '[]';`,
	},
	{
		`alter table password add column name text not null default '';`,
		`alter table password add column email_verified boolean;`,
	},
}
