package database

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=ON")
	if err != nil {
		return nil, fmt.Errorf("open database %s: %w", path, err)
	}

	db.SetMaxOpenConns(1)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	// Belt-and-suspenders: modernc.org/sqlite's URL-param pragma handling
	// varies by version, so apply the important ones explicitly here.
	// WAL gives us concurrent reader + writer semantics so the HTTP
	// handler and the refresh-cron goroutine don't step on each other.
	// busy_timeout avoids SQLITE_BUSY returns under normal contention.
	// foreign_keys=ON enforces CASCADE on device_policies when a policy
	// is deleted.
	for _, stmt := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
		"PRAGMA synchronous=NORMAL",
	} {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("pragma %q: %w", stmt, err)
		}
	}

	if err := Migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	return db, nil
}
