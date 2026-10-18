![CRIMSONLOCO logo](static/CRIMSONLOCO-logo.png)

# CRIMSONLOCO

A tool for the responsible red team that tracks hosts and artifacts during
an operation. Built for operational organization, cleanup, and
deconfliction purposes. A simple, lightweight, and performant self-hosted
webapp that consists of a single Go binary and SQLite database. The only
dependency besides the Go standard library is `github.com/mattn/go-sqlite3`.

## Build

Needs Go 1.24+ and a C compiler (go-sqlite3 uses cgo).

```sh
go mod download
go build -o CRIMSONLOCO .
```

## Run

Run it from this directory, so it finds `templates/` and `static/`:

```sh
./CRIMSONLOCO
```

Open https://localhost:8443 and accept the self-signed certificate warning.
The certificate and key (`server.crt`, `server.key`) are created on first
run if they are missing. On every start the program prints the
certificate's SHA256 fingerprint; compare it with the fingerprint your
browser shows in the certificate details for the site to confirm you are
connecting to this server and not something in between.

## First-time setup

There is nothing to set up by hand. On startup the program:

1. Creates the database file (`CRIMSONLOCO.db`) if it does not exist.
2. Creates the tables if they are missing, and adds any missing columns to
   tables that already exist (your data is kept).
3. Creates an `admin` user if there are no users yet. Set the password
   yourself with the environment variable below, otherwise a random one is
   printed to the console once. After logging in, change it from the menu
   under your username in the upper right.

```sh
CRIMSONLOCO_ADMIN_PASSWORD='pick-a-strong-one' ./CRIMSONLOCO
```

If the file at the database path is not a SQLite database, the program
exits with an error telling you to rename or delete it.

Roles: there are admins and operators. Both can add hosts and edit any
field. Only admins can view the Administration page, add an Operation, or
delete anything (hosts, operations, users).

## Configuration

Normally you run it with no arguments at all. All settings live in a plain
text file, `CRIMSONLOCO.conf`, which ships with the program and is read
from the working directory on every start. One setting per line.

Edit it and restart to change a setting. If the file is missing, the
program writes a new one with the defaults and carries on. To use a
different file: `./CRIMSONLOCO --config /path/to/other.conf`.

Any setting can still be overridden for a single run on the command line,
using the same names. Command line wins over the config file. Long options
take two dashes, short options one dash and one letter:

```
-v, --version        -h, --help
--addr :8443         --db CRIMSONLOCO.db    --templates templates
--static static      --cert server.crt     --key server.key    --config PATH
```

## Notes

- Passwords are stored as PBKDF2-HMAC-SHA256 hashes with a random salt per
  user (600,000 iterations). Sessions are stored in the database, last 8
  hours, and are deleted server-side on logout.
- Five failed login attempts within 15 minutes lock the account for 15
  minutes; attempts during the lock are refused without checking the
  password. A successful login clears the count, and the counts are kept
  in memory only, so restarting the program clears them too.
- Multiple people can be logged in at once. Database writes are serialized,
  so they cannot corrupt or lock each other out. Host edits use a version
  number: if someone else saves a host while you are editing it, your save
  is rejected with an explanation instead of silently overwriting theirs.
- Developed with assistance from Meta Muse. Not affiliated with or
  endorsed by Meta Platforms, Inc. All code has been reviewed and vetted
  by a human, me.
