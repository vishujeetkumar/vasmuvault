# VasmuVault Pro

Secure admin-only file & folder vault built with **PHP 8.2+** and **MySQL 5.7+ / MariaDB 10.3+**.
Files are stored inside MySQL (in small chunks) and **encrypted at rest** with libsodium (XChaCha20-Poly1305).
Folders marked "Public" are shown on a public portfolio page; the admin panel lives at `?admin=1`.

## Features

- Admin-only login (Argon2id / bcrypt), brute-force throttling, session hardening, idle/absolute timeouts
- Upload multiple files or an entire folder, create folders
- Dashboard: total files / folders / storage, search, filter, pagination, download, delete
- Public portfolio page for selected folders
- CSRF protection, strict CSP with nonces, security headers, audit log, safe download headers
- Works on shared hosting (e.g. InfinityFree)

## Requirements

- PHP 8.2+ with extensions: `pdo_mysql`, `sodium`, `fileinfo`
- MySQL 5.7+ or MariaDB 10.3+
- Apache with `.htaccess` support

## Setup

### 1. Database

Create a MySQL database, then import `schema.sql`.

```bash
mysql -u root -p < schema.sql
```

On shared hosting (InfinityFree etc.): create the database in the hosting panel, open phpMyAdmin, select it and import `schema.sql` (remove the `CREATE DATABASE` and `USE` lines first).
The app also creates the tables automatically on first run if they are missing.

> Do not upload `schema.sql` to the web server. It is only needed for the import.

### 2. Configuration

Create `Vasmuvault.config.php` **one level above** the web root (or next to `index.php`):

```php
<?php
return [
    'db_host'   => '127.0.0.1',          // InfinityFree: e.g. sql123.infinityfree.com
    'db_name'   => 'file_manager_db',
    'db_user'   => 'Vasmuvault',
    'db_pass'   => 'your-db-password',
    'app_key'   => 'BASE64_OF_32_RANDOM_BYTES',
    'setup_key' => 'a-long-one-time-secret',

    'center_name'    => 'Your Center Name',
    'center_tagline' => 'Student Projects & Work',
    'center_contact' => 'Phone: 98xxxxxx10 | City, State',
];
```

All options can also be set with environment variables prefixed `CV_` (e.g. `CV_DB_PASS`, `CV_APP_KEY`).

#### Generating `app_key`

`app_key` is the encryption key for every stored file. Generate it with any one of:

```bash
php -r "echo base64_encode(random_bytes(32));"
python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"
```

Or in the browser console:

```js
btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))
```

> **Back up this key.** If it is lost or changed, previously uploaded files can no longer be decrypted.

### 3. First run

1. Upload `index.php` and `.htaccess` to your server.
2. Open `https://your-site/index.php?admin=1`.
3. Create the first admin account using your `setup_key`.
4. You can remove `setup_key` from the config afterwards.

## Configuration options

| Option | Default | Description |
|---|---|---|
| `db_host`, `db_port`, `db_name`, `db_user`, `db_pass` | see file | MySQL connection |
| `db_auto_create` | `false` | Create the database automatically (own server only) |
| `app_key` | – | **Required.** Base64 of 32 random bytes |
| `setup_key` | – | One-time secret to create the first admin |
| `max_file_mb` | `15` | Max upload size (also limited by PHP settings) |
| `chunk_kb` | `512` | DB row size for file chunks |
| `block_executables` | `true` | Refuse `.php`, `.exe`, `.sh` ... uploads |
| `require_https` | `true` | Force HTTPS (localhost exempt) |
| `session_idle_minutes` / `session_max_hours` | `30` / `8` | Session timeouts |
| `public_indexable` | `false` | Allow search engines to index the portfolio |

## Security notes

- Never commit `Vasmuvault.config.php` (add it to `.gitignore`).
- Use a dedicated MySQL user, not `root`.
- Keep a safe backup of `app_key`.
- `.htaccess` blocks access to `.sql`, `.log`, `.ini`, backup files and `Vasmuvault.config.php`.

## Project structure

```
index.php      # entire application (admin + public portfolio)
.htaccess      # Apache rules
schema.sql     # database schema (import only, do not upload to server)
```
