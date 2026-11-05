<?php
declare(strict_types=1);

/**
 * VasmuVault Pro - Secure Admin File & Folder Vault (PHP 8.2+ / MySQL 5.7+ / MariaDB 10.3+)
 *
 * Features
 *  - Admin-only login (Argon2id/bcrypt, brute-force throttling, session hardening, idle/absolute timeouts)
 *  - Option 1: Upload multiple files OR an entire folder, create folders
 *  - Option 2: Dashboard with total files / folders / storage, search, filter, pagination, download, delete
 *  - Files are stored in MySQL in small chunks and encrypted at rest (XChaCha20-Poly1305 via libsodium)
 *  - CSRF protection, strict CSP with nonces, security headers, audit log, safe download headers
 *
 * Public portfolio: folders you mark "Public" are shown at the site root (index.php) for clients; admin is at ?admin=1
 * Works on shared hosting (e.g. InfinityFree): see the comments next to db_host, max_file_mb and db_auto_create.
 *
 * First run: fill in the CONFIG block below (or use CV_* environment variables), open the page
 * in your browser and create the admin account with your setup_key.
 */

if (PHP_VERSION_ID < 80200) {
    http_response_code(500);
    exit('VasmuVault requires PHP 8.2 or newer.');
}
foreach (['pdo_mysql', 'sodium', 'fileinfo'] as $ext) {
    if (!extension_loaded($ext)) {
        http_response_code(500);
        exit('Required PHP extension missing: ' . $ext);
    }
}

// ============================================================================
// 1. CONFIGURATION
//    Best practice: keep secrets OUTSIDE the web root, either in environment variables
//    (CV_DB_PASS, CV_APP_KEY, CV_SETUP_KEY ...) or in ../Vasmuvault.config.php returning an array.
// ============================================================================
function config(string $key): string|int|bool
{
    static $cfg = null;
    if ($cfg === null) {
        $cfg = [
            'db_host'              => '127.0.0.1',    // InfinityFree: use the host shown in its panel, e.g. sql123.infinityfree.com
            'db_port'              => 3306,
            'db_name'              => 'file_manager_db',
            'db_user'              => 'Vasmuvault',   // dedicated MySQL user (InfinityFree: if0_XXXXXXX), NOT root
            'db_pass'              => '',
            'db_auto_create'       => false,          // true only on your own server; free hosts: create the DB in the panel
            'app_key'              => '',             // base64 of 32 random bytes (encryption key) - REQUIRED
            'setup_key'            => '',             // one-time secret needed to create the first admin
            'max_file_mb'          => 15,             // InfinityFree PHP upload limit is 20 MB; raise on better hosting
            'chunk_kb'             => 512,            // DB row size; small = safe on hosts with a low max_allowed_packet
            'block_executables'    => true,           // refuse .php/.exe/.sh/... uploads
            'require_https'        => true,           // localhost is exempt
            'trust_proxy'          => false,          // true only behind your own reverse proxy
            'session_idle_minutes' => 30,
            'session_max_hours'    => 8,
            'timezone'             => 'UTC',
            'center_name'          => 'Raj Computer',                          // shown on the public portfolio
            'center_tagline'       => 'ADCA Course - Student Projects & Work',
            'center_contact'       => '',                                      // e.g. 'Phone: 98xxxxxx10 | City, State'
            'public_indexable'     => false,                                   // true = allow Google to index the portfolio
        ];
        foreach ([dirname(__DIR__) . '/Vasmuvault.config.php', __DIR__ . '/Vasmuvault.config.php'] as $external) {
            if (is_file($external)) {
                $over = require $external;
                if (is_array($over)) {
                    foreach ($over as $k => $v) {
                        if (array_key_exists($k, $cfg) && get_debug_type($v) === get_debug_type($cfg[$k])) {
                            $cfg[$k] = $v;
                        }
                    }
                }
                break;
            }
        }
        foreach ($cfg as $k => $default) {
            $env = getenv('CV_' . strtoupper($k));
            if ($env !== false && $env !== '') {
                $cfg[$k] = is_bool($default)
                    ? filter_var($env, FILTER_VALIDATE_BOOLEAN)
                    : (is_int($default) ? (int) $env : $env);
            }
        }
    }
    return $cfg[$key];
}

const PER_PAGE          = 20;
const LOGIN_WINDOW_MIN  = 15;
const MAX_FAIL_PER_IP   = 5;
const MAX_FAIL_PER_USER = 30;
const PREVIEW_MAX_BYTES = 3145728; // only images up to 3 MB are previewed inline on the public site
const SAFE_IMAGE_MIMES  = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
const BLOCKED_EXT       = ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'pht', 'phps', 'phar',
                           'exe', 'dll', 'msi', 'bat', 'cmd', 'scr', 'vbs', 'ps1', 'sh', 'cgi', 'jar', 'htaccess'];

date_default_timezone_set((string) config('timezone'));
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

// ============================================================================
// 2. LOW-LEVEL HELPERS
// ============================================================================
function e(?string $v): string
{
    return htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function nonce(): string
{
    static $n = null;
    return $n ??= bin2hex(random_bytes(16));
}

function selfUrl(array $q = []): string
{
    $base = basename((string) ($_SERVER['SCRIPT_NAME'] ?? 'index.php'));
    return $q ? $base . '?' . http_build_query($q) : $base;
}

function redirect(string $url): never
{
    header('Location: ' . $url, true, 303);
    exit;
}

function clientIp(): string
{
    return substr((string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'), 0, 45);
}

function isHttps(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
        return true;
    }
    if ((int) ($_SERVER['SERVER_PORT'] ?? 0) === 443) {
        return true;
    }
    return (bool) config('trust_proxy')
        && strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
}

function isLoopback(): bool
{
    return in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true);
}

function formatBytes(int $bytes): string
{
    if ($bytes <= 0) {
        return '0 B';
    }
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $power = min((int) floor(log($bytes, 1024)), count($units) - 1);
    return round($bytes / (1024 ** $power), 2) . ' ' . $units[$power];
}

function iniBytes(string $v): int
{
    $v = trim($v);
    if ($v === '' || $v === '0') {
        return PHP_INT_MAX;
    }
    $n = (int) $v;
    return match (strtolower(substr($v, -1))) {
        'g'     => $n * 1024 ** 3,
        'm'     => $n * 1024 ** 2,
        'k'     => $n * 1024,
        default => $n,
    };
}

function chunkBytes(): int
{
    return max(64, min(4096, (int) config('chunk_kb'))) * 1024;
}

function maxFileBytes(): int
{
    return min((int) config('max_file_mb') * 1048576, iniBytes((string) ini_get('upload_max_filesize')));
}

function sendSecurityHeaders(): void
{
    $n = nonce();
    header_remove('X-Powered-By');
    header("Content-Security-Policy: default-src 'none'; style-src 'nonce-$n'; script-src 'nonce-$n'; "
        . "img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('X-Robots-Tag: noindex, nofollow');
    header('Cache-Control: no-store, max-age=0');
    if (isHttps()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

function fatalPage(int $code, string $title, string $html): never
{
    http_response_code($code);
    pageStart($title);
    echo '<div class="card login-box"><h2>' . e($title) . '</h2>' . $html . '</div>';
    pageEnd();
    exit;
}

set_exception_handler(static function (Throwable $t): void {
    error_log('[VasmuVault] ' . get_class($t) . ': ' . $t->getMessage() . ' @ ' . $t->getFile() . ':' . $t->getLine());
    if (!headers_sent()) {
        sendSecurityHeaders();
    }
    fatalPage(500, 'Something went wrong', '<p class="muted">The error was logged on the server. Please try again.</p>');
});

// ============================================================================
// 3. FILE-NAME SANITISING
// ============================================================================
function cleanSegment(string $s, int $maxBytes): string
{
    if (!preg_match('//u', $s)) {
        $s = (string) preg_replace('/[^\x20-\x7E]/', '_', $s);
    }
    $s = (string) preg_replace('/[\x00-\x1F\x7F]+/u', '', $s);
    // strip invisible / bidi-override characters used for filename spoofing (e.g. "invoice\u202Efdp.exe")
    $s = (string) preg_replace('/[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FEFF}]/u', '', $s);
    $s = str_replace(['/', '\\'], '_', $s);
    $s = ltrim(rtrim($s, '. '), ' ');
    if (function_exists('mb_strcut')) {
        $s = mb_strcut($s, 0, $maxBytes, 'UTF-8');
    } else {
        $s = substr($s, 0, $maxBytes);
    }
    return $s;
}

function lastPathPart(string $path): string
{
    $parts = explode('/', str_replace('\\', '/', $path));
    return (string) end($parts);
}

function cleanText(string $s, int $maxBytes): string
{
    if (!preg_match('//u', $s)) {
        $s = (string) preg_replace('/[^\x20-\x7E\n]/', '?', $s);
    }
    $s = str_replace("\r", '', $s);
    $s = (string) preg_replace('/[\x00-\x09\x0B-\x1F\x7F]+/u', '', $s);
    $s = (string) preg_replace('/[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FEFF}]/u', '', $s);
    $s = (string) preg_replace("/\n{3,}/", "\n\n", trim($s));
    return function_exists('mb_strcut') ? mb_strcut($s, 0, $maxBytes, 'UTF-8') : substr($s, 0, $maxBytes);
}

// ============================================================================
// 4. ENCRYPTION AT REST (libsodium XChaCha20-Poly1305)
// ============================================================================
function appKey(): ?string
{
    static $key = false;
    if ($key === false) {
        $raw = base64_decode((string) config('app_key'), true);
        $key = ($raw !== false && strlen($raw) === SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) ? $raw : null;
    }
    return $key;
}

function encryptChunk(string $plain, int $fileId, int $index): string
{
    $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
    $ad    = pack('J2', $fileId, $index); // binds ciphertext to its file + position (anti-reorder)
    return $nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plain, $ad, $nonce, (string) appKey());
}

function decryptChunk(string $blob, int $fileId, int $index): string
{
    $nl = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    if (strlen($blob) <= $nl) {
        throw new RuntimeException('Corrupt chunk');
    }
    $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
        substr($blob, $nl), pack('J2', $fileId, $index), substr($blob, 0, $nl), (string) appKey()
    );
    if ($plain === false) {
        throw new RuntimeException('Chunk authentication failed (wrong app_key or tampered data)');
    }
    return $plain;
}

// ============================================================================
// 5. DATABASE
// ============================================================================
function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $name = (string) config('db_name');
    if (!preg_match('/^[A-Za-z0-9_]{1,64}$/', $name)) {
        throw new RuntimeException('Invalid db_name');
    }
    $opts = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];
    $dsn = static fn (bool $withDb): string => sprintf(
        'mysql:host=%s;port=%d;%scharset=utf8mb4', config('db_host'), config('db_port'), $withDb ? "dbname=$name;" : ''
    );
    try {
        $pdo = new PDO($dsn(true), (string) config('db_user'), (string) config('db_pass'), $opts);
    } catch (PDOException $e) {
        if ((int) ($e->errorInfo[1] ?? 0) === 1049 && config('db_auto_create')) {
            $tmp = new PDO($dsn(false), (string) config('db_user'), (string) config('db_pass'), $opts);
            $tmp->exec("CREATE DATABASE IF NOT EXISTS `$name` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            $pdo = new PDO($dsn(true), (string) config('db_user'), (string) config('db_pass'), $opts);
        } else {
            throw $e;
        }
    }
    ensureSchema($pdo);
    return $pdo;
}

function ensureSchema(PDO $pdo): void
{
    $missing = false;
    try {
        $pdo->query('SELECT 1 FROM `file_chunks` LIMIT 1')->closeCursor();
    } catch (PDOException $e) {
        if ((string) $e->getCode() !== '42S02') {
            throw $e;
        }
        $missing = true;
    }
    if (!$missing) {
        // upgrade older installs: add portfolio columns to `folders`
        try {
            $pdo->query('SELECT `is_public`, `description` FROM `folders` LIMIT 1')->closeCursor();
        } catch (PDOException $e) {
            if ((string) $e->getCode() !== '42S22') {
                throw $e;
            }
            $pdo->exec("ALTER TABLE `folders`
                ADD COLUMN `description` VARCHAR(500) NOT NULL DEFAULT '',
                ADD COLUMN `is_public` TINYINT(1) NOT NULL DEFAULT 0,
                ADD INDEX `idx_folders_public` (`is_public`)");
        }
        return;
    }
    $tail = 'ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci';
    $pdo->exec("CREATE TABLE IF NOT EXISTS `admins` (
        `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `username` VARCHAR(64) NOT NULL UNIQUE,
        `password_hash` VARCHAR(255) NOT NULL,
        `last_login_at` DATETIME NULL,
        `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) $tail");
    $pdo->exec("CREATE TABLE IF NOT EXISTS `folders` (
        `id` INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `folder_name` VARCHAR(190) NOT NULL UNIQUE,
        `description` VARCHAR(500) NOT NULL DEFAULT '',
        `is_public` TINYINT(1) NOT NULL DEFAULT 0,
        `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX `idx_folders_public` (`is_public`)
    ) $tail");
    $pdo->exec("CREATE TABLE IF NOT EXISTS `files` (
        `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `folder_id` INT UNSIGNED NULL,
        `original_name` VARCHAR(255) NOT NULL,
        `rel_path` VARCHAR(700) NOT NULL DEFAULT '',
        `mime_type` VARCHAR(150) NOT NULL DEFAULT 'application/octet-stream',
        `file_size` BIGINT UNSIGNED NOT NULL DEFAULT 0,
        `sha256` CHAR(64) NOT NULL,
        `chunk_count` INT UNSIGNED NOT NULL DEFAULT 0,
        `uploaded_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX `idx_files_folder` (`folder_id`),
        INDEX `idx_files_uploaded` (`uploaded_at`),
        CONSTRAINT `fk_files_folder` FOREIGN KEY (`folder_id`) REFERENCES `folders`(`id`) ON DELETE SET NULL
    ) $tail");
    $pdo->exec("CREATE TABLE IF NOT EXISTS `file_chunks` (
        `file_id` BIGINT UNSIGNED NOT NULL,
        `chunk_index` INT UNSIGNED NOT NULL,
        `data` MEDIUMBLOB NOT NULL,
        PRIMARY KEY (`file_id`, `chunk_index`),
        CONSTRAINT `fk_chunks_file` FOREIGN KEY (`file_id`) REFERENCES `files`(`id`) ON DELETE CASCADE
    ) $tail");
    $pdo->exec("CREATE TABLE IF NOT EXISTS `login_attempts` (
        `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `ip` VARCHAR(45) NOT NULL,
        `username` VARCHAR(64) NOT NULL,
        `attempted_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX `idx_la_ip` (`ip`, `attempted_at`),
        INDEX `idx_la_user` (`username`, `attempted_at`)
    ) $tail");
    $pdo->exec("CREATE TABLE IF NOT EXISTS `audit_log` (
        `id` BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        `admin_username` VARCHAR(64) NOT NULL DEFAULT '',
        `action` VARCHAR(40) NOT NULL,
        `detail` VARCHAR(500) NOT NULL DEFAULT '',
        `ip` VARCHAR(45) NOT NULL,
        `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) $tail");
}

function audit(PDO $pdo, string $action, string $detail = '', ?string $user = null): void
{
    $user ??= (string) ($_SESSION['admin_user'] ?? '');
    $pdo->prepare('INSERT INTO audit_log (admin_username, action, detail, ip) VALUES (?, ?, ?, ?)')
        ->execute([substr($user, 0, 64), substr($action, 0, 40), substr($detail, 0, 500), clientIp()]);
}

// ============================================================================
// 6. SESSION, CSRF, FLASH, LOGIN THROTTLING
// ============================================================================
function startSession(): void
{
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_trans_sid', '0');
    $secure = isHttps();
    session_name($secure ? '__Host-cvsid' : 'cvsid');
    session_set_cookie_params([
        'lifetime' => 0, 'path' => '/', 'domain' => '',
        'secure' => $secure, 'httponly' => true, 'samesite' => 'Strict',
    ]);
    session_start();
}

function resetSession(): void
{
    $_SESSION = [];
    session_regenerate_id(true);
}

function uaHash(): string
{
    return hash('sha256', (string) ($_SERVER['HTTP_USER_AGENT'] ?? ''));
}

function sessionIsValid(): bool
{
    if (empty($_SESSION['admin_id'])) {
        return false;
    }
    $now = time();
    $expired = ($now - (int) ($_SESSION['last_seen'] ?? 0)) > (int) config('session_idle_minutes') * 60
        || ($now - (int) ($_SESSION['login_at'] ?? 0)) > (int) config('session_max_hours') * 3600
        || !hash_equals((string) ($_SESSION['ua'] ?? ''), uaHash());
    if ($expired) {
        resetSession();
        flash('error', 'Session expired. Please log in again.');
        return false;
    }
    $_SESSION['last_seen'] = $now;
    return true;
}

function csrfToken(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return (string) $_SESSION['csrf'];
}

function csrfField(): string
{
    return '<input type="hidden" name="csrf_token" value="' . e(csrfToken()) . '">';
}

function verifyCsrf(): bool
{
    $t = $_POST['csrf_token'] ?? null;
    return is_string($t) && isset($_SESSION['csrf']) && hash_equals((string) $_SESSION['csrf'], $t);
}

function flash(string $type, string $msg): void
{
    $_SESSION['flash'] = ['type' => $type, 'msg' => $msg];
}

function pullFlash(): ?array
{
    $f = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    return is_array($f) ? $f : null;
}

function isThrottled(PDO $pdo, string $ip, string $user): bool
{
    $pdo->exec('DELETE FROM login_attempts WHERE attempted_at < (NOW() - INTERVAL 1 DAY)');
    $w = LOGIN_WINDOW_MIN;
    $a = $pdo->prepare("SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND attempted_at > (NOW() - INTERVAL $w MINUTE)");
    $a->execute([$ip]);
    if ((int) $a->fetchColumn() >= MAX_FAIL_PER_IP) {
        return true;
    }
    $b = $pdo->prepare("SELECT COUNT(*) FROM login_attempts WHERE username = ? AND attempted_at > (NOW() - INTERVAL $w MINUTE)");
    $b->execute([$user]);
    return (int) $b->fetchColumn() >= MAX_FAIL_PER_USER;
}

function recordFailure(PDO $pdo, string $ip, string $user): void
{
    $pdo->prepare('INSERT INTO login_attempts (ip, username) VALUES (?, ?)')->execute([$ip, substr($user, 0, 64)]);
}

function passwordAlgo(): string
{
    return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
}

// ============================================================================
// 7. ACTIONS
// ============================================================================
function handleSetup(PDO $pdo): never
{
    $setupKey = (string) config('setup_key');
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form_action'] ?? '') === 'setup') {
        $ip = clientIp();
        if (!verifyCsrf()) {
            flash('error', 'Security token mismatch. Please try again.');
        } elseif ($setupKey === '') {
            flash('error', 'setup_key is not configured on the server.');
        } elseif (isThrottled($pdo, $ip, '__setup__')) {
            flash('error', 'Too many attempts. Try again later.');
        } else {
            $user = trim((string) ($_POST['username'] ?? ''));
            $pass = (string) ($_POST['password'] ?? '');
            $conf = (string) ($_POST['password2'] ?? '');
            $key  = (string) ($_POST['setup_key'] ?? '');
            if (!hash_equals($setupKey, $key)) {
                recordFailure($pdo, $ip, '__setup__');
                flash('error', 'Invalid setup key.');
            } elseif (!preg_match('/^[A-Za-z0-9_.-]{3,64}$/', $user)) {
                flash('error', 'Username must be 3-64 characters: letters, numbers, . _ -');
            } elseif (strlen($pass) < 12) {
                flash('error', 'Password must be at least 12 characters.');
            } elseif (!hash_equals($pass, $conf)) {
                flash('error', 'Passwords do not match.');
            } elseif ((int) $pdo->query('SELECT COUNT(*) FROM admins')->fetchColumn() > 0) {
                flash('error', 'Setup is already completed.');
            } else {
                $pdo->prepare('INSERT INTO admins (username, password_hash) VALUES (?, ?)')
                    ->execute([$user, password_hash($pass, passwordAlgo())]);
                audit($pdo, 'admin_created', $user, $user);
                flash('success', 'Admin created. You can log in now. (You may remove setup_key from the config.)');
            }
        }
        redirect(selfUrl(['admin' => '1']));
    }
    renderSetup($setupKey !== '');
    exit;
}

function handleLogin(PDO $pdo): never
{
    $ip   = clientIp();
    $user = substr(trim((string) ($_POST['username'] ?? '')), 0, 64);
    $pass = (string) ($_POST['password'] ?? '');

    if (!verifyCsrf()) {
        flash('error', 'Security token mismatch. Please try again.');
        redirect(selfUrl(['admin' => '1']));
    }
    if (isThrottled($pdo, $ip, $user)) {
        audit($pdo, 'login_blocked', 'throttled', $user);
        flash('error', 'Too many failed attempts. Please try again in ' . LOGIN_WINDOW_MIN . ' minutes.');
        redirect(selfUrl(['admin' => '1']));
    }

    $st = $pdo->prepare('SELECT id, username, password_hash FROM admins WHERE username = ? LIMIT 1');
    $st->execute([$user]);
    $row = $st->fetch();

    // Always run a hash verification so response time does not reveal whether the user exists
    static $dummy = null;
    $dummy ??= password_hash('Vasmuvault-dummy', passwordAlgo());
    $valid = password_verify($pass, $row ? (string) $row['password_hash'] : $dummy) && $row !== false;

    if (!$valid) {
        recordFailure($pdo, $ip, $user);
        audit($pdo, 'login_failed', '', $user);
        usleep(random_int(250000, 600000));
        flash('error', 'Invalid username or password.');
        redirect(selfUrl(['admin' => '1']));
    }

    if (password_needs_rehash((string) $row['password_hash'], passwordAlgo())) {
        $pdo->prepare('UPDATE admins SET password_hash = ? WHERE id = ?')
            ->execute([password_hash($pass, passwordAlgo()), $row['id']]);
    }
    $pdo->prepare('DELETE FROM login_attempts WHERE ip = ?')->execute([$ip]);
    $pdo->prepare('UPDATE admins SET last_login_at = NOW() WHERE id = ?')->execute([$row['id']]);

    resetSession(); // new session id on privilege change (anti session-fixation)
    $_SESSION['admin_id']   = (int) $row['id'];
    $_SESSION['admin_user'] = (string) $row['username'];
    $_SESSION['login_at']   = time();
    $_SESSION['last_seen']  = time();
    $_SESSION['ua']         = uaHash();
    audit($pdo, 'login', '', (string) $row['username']);
    redirect(selfUrl(['tab' => 'browse']));
}

function normalizeFiles(string $field): array
{
    $out = [];
    if (!isset($_FILES[$field]) || !is_array($_FILES[$field]['name'] ?? null)) {
        return $out;
    }
    $f = $_FILES[$field];
    foreach ($f['name'] as $i => $name) {
        if (!is_string($name) || !is_string($f['tmp_name'][$i] ?? null)) {
            continue;
        }
        $out[] = [
            'name'      => $name,
            'full_path' => is_string($f['full_path'][$i] ?? null) ? $f['full_path'][$i] : $name,
            'tmp_name'  => $f['tmp_name'][$i],
            'error'     => (int) ($f['error'][$i] ?? UPLOAD_ERR_NO_FILE),
            'size'      => (int) ($f['size'][$i] ?? 0),
        ];
    }
    return $out;
}

function getOrCreateFolder(PDO $pdo, string $name): int
{
    $pdo->prepare('INSERT INTO folders (folder_name) VALUES (?) ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)')
        ->execute([$name]);
    return (int) $pdo->lastInsertId();
}

function readFull($h, int $len): string
{
    $buf = '';
    while (strlen($buf) < $len && !feof($h)) {
        $piece = fread($h, $len - strlen($buf));
        if ($piece === false || $piece === '') {
            break;
        }
        $buf .= $piece;
    }
    return $buf;
}

/** @return array{0:bool,1:string} [ok, message] */
function storeFile(PDO $pdo, array $f, string $name, ?int $folderId, string $relPath): array
{
    $err = $f['error'];
    if ($err !== UPLOAD_ERR_OK) {
        return [false, match ($err) {
            UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'exceeds server upload limit',
            UPLOAD_ERR_PARTIAL                        => 'partially uploaded',
            default                                   => 'upload error ' . $err,
        }];
    }
    if ($name === '') {
        return [false, 'invalid file name'];
    }
    if ($f['size'] > maxFileBytes()) {
        return [false, 'larger than ' . formatBytes(maxFileBytes())];
    }
    if (!is_uploaded_file($f['tmp_name'])) {
        return [false, 'invalid upload'];
    }
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if (config('block_executables') && (in_array($ext, BLOCKED_EXT, true) || preg_match('/\.ph(p\d?|tml|ar)(\.|$)/i', $name))) {
        return [false, 'executable/script file types are blocked'];
    }

    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($f['tmp_name']) ?: 'application/octet-stream';
    if (!preg_match('#^[\w.+-]+/[\w.+-]+$#', $mime) || strlen($mime) > 150) {
        $mime = 'application/octet-stream';
    }
    $h = fopen($f['tmp_name'], 'rb');
    if ($h === false) {
        return [false, 'cannot read upload'];
    }

    try {
        $pdo->beginTransaction();
        $pdo->prepare('INSERT INTO files (folder_id, original_name, rel_path, mime_type, file_size, sha256, chunk_count)
                       VALUES (?, ?, ?, ?, 0, ?, 0)')
            ->execute([$folderId, $name, $relPath, $mime, str_repeat('0', 64)]);
        $fileId = (int) $pdo->lastInsertId();

        $ins = $pdo->prepare('INSERT INTO file_chunks (file_id, chunk_index, data) VALUES (?, ?, ?)');
        $ctx = hash_init('sha256');
        $total = 0;
        $idx = 0;
        while (($buf = readFull($h, chunkBytes())) !== '') {
            $total += strlen($buf);
            if ($total > maxFileBytes()) {
                throw new LengthException('too large');
            }
            hash_update($ctx, $buf);
            $ins->execute([$fileId, $idx, encryptChunk($buf, $fileId, $idx)]);
            $idx++;
        }
        $pdo->prepare('UPDATE files SET file_size = ?, sha256 = ?, chunk_count = ? WHERE id = ?')
            ->execute([$total, hash_final($ctx), $idx, $fileId]);
        $pdo->commit();
    } catch (Throwable $t) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('[VasmuVault] store failed: ' . $t->getMessage());
        return [false, $t instanceof LengthException ? 'file too large' : 'database error (see server log)'];
    } finally {
        fclose($h);
    }
    return [true, formatBytes($total)];
}

function handleUpload(PDO $pdo, string $mode): void
{
    @set_time_limit(600);
    $files = normalizeFiles($mode === 'folder' ? 'dir' : 'files');
    $files = array_values(array_filter($files, static fn ($f) => $f['error'] !== UPLOAD_ERR_NO_FILE));
    if (!$files) {
        flash('error', 'Please choose at least one file.');
        return;
    }

    $destFolder = null;
    if ($mode === 'files') {
        $in = $_POST['folder_id'] ?? '';
        if (is_string($in) && ctype_digit($in) && $in !== '') {
            $chk = $pdo->prepare('SELECT id FROM folders WHERE id = ?');
            $chk->execute([(int) $in]);
            if ($chk->fetchColumn() === false) {
                flash('error', 'Selected folder does not exist.');
                return;
            }
            $destFolder = (int) $in;
        }
    }

    $ok = 0;
    $bad = [];
    $folderCache = [];
    foreach ($files as $f) {
        $folderId = $destFolder;
        $rel = '';
        if ($mode === 'folder') {
            $parts = array_values(array_filter(
                array_map(static fn ($p) => cleanSegment($p, 190), explode('/', str_replace('\\', '/', $f['full_path']))),
                static fn ($p) => $p !== '' && $p !== '.' && $p !== '..'
            ));
            $name = $parts ? array_pop($parts) : '';
            if ($parts) {
                $top = array_shift($parts);
                $folderCache[$top] ??= getOrCreateFolder($pdo, $top);
                $folderId = $folderCache[$top];
                $rel = substr(implode('/', $parts), 0, 700);
            }
        } else {
            $name = cleanSegment(lastPathPart($f['name']), 255);
        }
        [$res, $msg] = storeFile($pdo, $f, $name, $folderId, $rel);
        if ($res) {
            $ok++;
        } else {
            $bad[] = ($name !== '' ? $name : 'file') . ' (' . $msg . ')';
        }
    }

    if ($ok > 0) {
        audit($pdo, 'upload', "$ok file(s) via $mode" . ($bad ? ', ' . count($bad) . ' failed' : ''));
    }
    $text = "Uploaded $ok file(s) securely.";
    if ($bad) {
        $text .= ' Failed: ' . implode('; ', array_slice($bad, 0, 5)) . (count($bad) > 5 ? '; ...' : '');
    }
    flash($bad && $ok === 0 ? 'error' : ($bad ? 'warning' : 'success'), $text);
}

function handlePost(PDO $pdo): never
{
    $action = (string) ($_POST['form_action'] ?? '');
    if ($action === '' && !$_POST && !$_FILES && (int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 0) {
        flash('error', 'Upload too large for the server (post_max_size = ' . ini_get('post_max_size') . ').');
        redirect(selfUrl(['tab' => 'upload']));
    }
    if (!verifyCsrf()) {
        flash('error', 'Security token mismatch. Please try again.');
        redirect(selfUrl(['tab' => 'browse']));
    }

    $next = ['tab' => 'browse'];
    switch ($action) {
        case 'logout':
            audit($pdo, 'logout');
            resetSession();
            redirect(selfUrl(['admin' => '1']));

        case 'create_folder':
            $next = ['tab' => 'upload'];
            $name = cleanSegment((string) ($_POST['folder_name'] ?? ''), 190);
            if ($name === '' || $name === '.' || $name === '..') {
                flash('error', 'Folder name cannot be empty.');
                break;
            }
            $st = $pdo->prepare('SELECT id FROM folders WHERE folder_name = ?');
            $st->execute([$name]);
            if ($st->fetchColumn() !== false) {
                flash('error', 'A folder with this name already exists.');
                break;
            }
            $desc = cleanText((string) ($_POST['description'] ?? ''), 500);
            $pub  = isset($_POST['is_public']) ? 1 : 0;
            $pdo->prepare('INSERT INTO folders (folder_name, description, is_public) VALUES (?, ?, ?)')->execute([$name, $desc, $pub]);
            audit($pdo, 'folder_create', $name . ($pub ? ' (public)' : ''));
            flash('success', 'Folder created' . ($pub ? ' and published to the portfolio.' : ' (private).'));
            break;

        case 'update_folder':
            $id = filter_var($_POST['folder_id'] ?? null, FILTER_VALIDATE_INT);
            if (!$id) {
                break;
            }
            $name = cleanSegment((string) ($_POST['folder_name'] ?? ''), 190);
            $desc = cleanText((string) ($_POST['description'] ?? ''), 500);
            $pub  = isset($_POST['is_public']) ? 1 : 0;
            if ($name === '' || $name === '.' || $name === '..') {
                flash('error', 'Folder name cannot be empty.');
                break;
            }
            try {
                $pdo->prepare('UPDATE folders SET folder_name = ?, description = ?, is_public = ? WHERE id = ?')->execute([$name, $desc, $pub, $id]);
                audit($pdo, 'folder_update', "#$id " . $name . ($pub ? ' (public)' : ' (private)'));
                flash('success', 'Folder updated - it is now ' . ($pub ? 'PUBLIC on the portfolio.' : 'private.'));
            } catch (PDOException $e) {
                flash('error', 'Another folder already uses this name.');
            }
            break;

        case 'upload_files':
        case 'upload_folder':
            $next = ['tab' => 'upload'];
            handleUpload($pdo, $action === 'upload_folder' ? 'folder' : 'files');
            break;

        case 'delete_file':
            $id = filter_var($_POST['file_id'] ?? null, FILTER_VALIDATE_INT);
            if ($id) {
                $st = $pdo->prepare('SELECT original_name FROM files WHERE id = ?');
                $st->execute([$id]);
                $nm = $st->fetchColumn();
                if ($nm !== false) {
                    $pdo->prepare('DELETE FROM files WHERE id = ?')->execute([$id]);
                    audit($pdo, 'file_delete', "#$id " . $nm);
                    flash('success', 'File deleted permanently.');
                }
            }
            break;

        case 'delete_folder':
            $id = filter_var($_POST['folder_id'] ?? null, FILTER_VALIDATE_INT);
            if ($id) {
                $st = $pdo->prepare('SELECT folder_name FROM folders WHERE id = ?');
                $st->execute([$id]);
                $nm = $st->fetchColumn();
                if ($nm !== false) {
                    $pdo->prepare('DELETE FROM folders WHERE id = ?')->execute([$id]);
                    audit($pdo, 'folder_delete', "#$id " . $nm);
                    flash('success', 'Folder deleted. Its files were moved to Root.');
                }
            }
            break;

        default:
            flash('error', 'Unknown action.');
    }
    redirect(selfUrl($next));
}

function loadFirstChunk(PDO $pdo, array $row): string|false
{
    if ((int) $row['chunk_count'] === 0) {
        return '';
    }
    try {
        $cs = $pdo->prepare('SELECT data FROM file_chunks WHERE file_id = ? AND chunk_index = 0');
        $cs->execute([(int) $row['id']]);
        $blob = $cs->fetchColumn();
        $cs->closeCursor();
        if ($blob === false) {
            throw new RuntimeException('Missing chunk 0');
        }
        return decryptChunk((string) $blob, (int) $row['id'], 0); // verified before any header is sent
    } catch (Throwable $t) {
        error_log('[VasmuVault] file #' . $row['id'] . ' unreadable: ' . $t->getMessage());
        return false;
    }
}

function sendFileHeaders(array $row, bool $inline, string $ctype): void
{
    $orig     = (string) $row['original_name'];
    $fallback = preg_replace('/[^A-Za-z0-9._-]/', '_', $orig) ?: 'download';
    header('Content-Type: ' . $ctype);
    header('Content-Disposition: ' . ($inline ? 'inline' : 'attachment') . '; filename="' . $fallback . '"; filename*=UTF-8\'\'' . rawurlencode($orig));
    header('Content-Length: ' . (int) $row['file_size']);
    header('Content-Security-Policy: default-src \'none\'; sandbox');
    header('X-Content-Type-Options: nosniff');
}

function streamFile(PDO $pdo, array $row, string $first): never
{
    @set_time_limit(0);
    ini_set('zlib.output_compression', '0');
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    echo $first;
    flush();
    $id = (int) $row['id'];
    $cs = $pdo->prepare('SELECT data FROM file_chunks WHERE file_id = ? AND chunk_index = ?');
    for ($i = 1; $i < (int) $row['chunk_count']; $i++) {
        if (connection_aborted()) {
            break;
        }
        $cs->execute([$id, $i]);
        $blob = $cs->fetchColumn();
        $cs->closeCursor();
        if ($blob === false) {
            error_log("[VasmuVault] file #$id missing chunk $i");
            break;
        }
        echo decryptChunk((string) $blob, $id, $i);
        flush();
    }
    exit;
}

function handleDownload(PDO $pdo, int $id): never
{
    $st = $pdo->prepare('SELECT id, original_name, file_size, chunk_count FROM files WHERE id = ?');
    $st->execute([$id]);
    $row = $st->fetch();
    if (!$row) {
        flash('error', 'Requested file was not found.');
        redirect(selfUrl(['tab' => 'browse']));
    }
    $first = loadFirstChunk($pdo, $row);
    if ($first === false) {
        flash('error', 'This file could not be decrypted or is corrupted.');
        redirect(selfUrl(['tab' => 'browse']));
    }
    audit($pdo, 'download', "#$id " . $row['original_name']);
    session_write_close(); // release the session lock during long transfers
    sendFileHeaders($row, false, 'application/octet-stream'); // never trust/serve the stored MIME type
    header('Cache-Control: private, no-store, max-age=0');
    streamFile($pdo, $row, $first);
}

// ============================================================================
// 7b. PUBLIC PORTFOLIO (no login) - only files inside folders marked "Public"
// ============================================================================
function notFoundPage(): never
{
    fatalPage(404, 'Not found', '<p class="muted">This page is not available.</p><p><a class="link" href="' . e(selfUrl()) . '">&larr; Back to portfolio</a></p>');
}

function isPreviewable(array $f): bool
{
    $size = (int) $f['file_size'];
    return in_array((string) $f['mime_type'], SAFE_IMAGE_MIMES, true) && $size > 0 && $size <= PREVIEW_MAX_BYTES;
}

function handlePublicFile(PDO $pdo, int $id, bool $inline): never
{
    $st = $pdo->prepare('SELECT fl.id, fl.original_name, fl.mime_type, fl.file_size, fl.chunk_count
                         FROM files fl JOIN folders fd ON fd.id = fl.folder_id
                         WHERE fl.id = ? AND fd.is_public = 1');
    $st->execute([$id]);
    $row = $st->fetch();
    if (!$row || ($inline && !isPreviewable($row))) {
        notFoundPage();
    }
    $first = loadFirstChunk($pdo, $row);
    if ($first === false) {
        fatalPage(500, 'File unavailable', '<p class="muted">This file cannot be opened right now.</p>');
    }
    sendFileHeaders($row, $inline, $inline ? (string) $row['mime_type'] : 'application/octet-stream');
    header('Cache-Control: public, max-age=600');
    streamFile($pdo, $row, $first);
}

function shorten(string $s, int $len): string
{
    if (function_exists('mb_strimwidth')) {
        return mb_strimwidth($s, 0, $len, '...', 'UTF-8');
    }
    return strlen($s) > $len ? substr($s, 0, $len - 3) . '...' : $s;
}

function publicHeader(): void
{
    $center = (string) config('center_name');
    $ini = '';
    foreach (array_slice(preg_split('/\s+/', trim($center)) ?: [], 0, 2) as $w) {
        if (preg_match('/^./u', $w, $m)) {
            $ini .= function_exists('mb_strtoupper') ? mb_strtoupper($m[0]) : strtoupper($m[0]);
        }
    }
    echo '<header class="hero"><div class="brand center-brand"><div class="brand-badge">' . e($ini ?: 'CV') . '</div><div><h1>' . e($center) . '</h1>'
        . '<p>' . e((string) config('center_tagline')) . '</p></div></div>'
        . (config('center_contact') !== '' ? '<p class="muted small">' . e((string) config('center_contact')) . '</p>' : '') . '</header>';
}

function publicFooter(): void
{
    echo '<p class="muted small center footer">&copy; ' . date('Y') . ' ' . e((string) config('center_name'))
        . ' &bull; <a class="link" href="' . e(selfUrl(['admin' => '1'])) . '">Admin</a></p>';
}

function renderPublic(PDO $pdo): never
{
    if (isset($_GET['f']) || isset($_GET['v'])) {
        $inline = isset($_GET['v']);
        $id = filter_var($_GET[$inline ? 'v' : 'f'], FILTER_VALIDATE_INT);
        if ($id === false || $id < 1) {
            notFoundPage();
        }
        handlePublicFile($pdo, $id, $inline);
    }

    $GLOBALS['cv_indexable'] = (bool) config('public_indexable');
    if ($GLOBALS['cv_indexable']) {
        header_remove('X-Robots-Tag');
    }
    header('Cache-Control: public, max-age=120');
    $center = (string) config('center_name');

    if (isset($_GET['p'])) {
        $pid = filter_var($_GET['p'], FILTER_VALIDATE_INT);
        if ($pid === false || $pid < 1) {
            notFoundPage();
        }
        $st = $pdo->prepare('SELECT id, folder_name, description FROM folders WHERE id = ? AND is_public = 1');
        $st->execute([$pid]);
        $proj = $st->fetch();
        if (!$proj) {
            notFoundPage();
        }
        $cnt = $pdo->prepare('SELECT COUNT(*) FROM files WHERE folder_id = ?');
        $cnt->execute([$pid]);
        $total = (int) $cnt->fetchColumn();
        $fs = $pdo->prepare('SELECT id, original_name, rel_path, mime_type, file_size FROM files
                             WHERE folder_id = ? ORDER BY rel_path, original_name LIMIT 200');
        $fs->execute([$pid]);
        $files = $fs->fetchAll();

        pageStart((string) $proj['folder_name'] . ' - ' . $center);
        publicHeader();
        echo '<a class="link back" href="' . e(selfUrl()) . '">&larr; All projects</a>'
            . '<div class="card"><h2>' . e((string) $proj['folder_name']) . '</h2>'
            . ($proj['description'] !== '' ? '<p class="muted desc">' . nl2br(e((string) $proj['description'])) . '</p>' : '')
            . '<p><span class="badge">' . $total . ' file(s)</span></p></div>';

        $images = array_values(array_filter($files, 'isPreviewable'));
        $others = array_values(array_filter($files, static fn ($f) => !isPreviewable($f)));
        if ($images) {
            echo '<div class="card"><h2>Gallery</h2><div class="gallery">';
            foreach ($images as $f) {
                echo '<figure><a href="' . e(selfUrl(['v' => (string) $f['id']])) . '"><img loading="lazy" src="' . e(selfUrl(['v' => (string) $f['id']]))
                    . '" alt="' . e((string) $f['original_name']) . '"></a><figcaption><span>' . e((string) $f['original_name'])
                    . '</span><a class="link" href="' . e(selfUrl(['f' => (string) $f['id']])) . '">Download</a></figcaption></figure>';
            }
            echo '</div></div>';
        }
        if ($others) {
            echo '<div class="card"><h2>Project files</h2><div class="table-wrap"><table><thead><tr><th>File</th><th>Type</th><th>Size</th><th></th></tr></thead><tbody>';
            foreach ($others as $f) {
                echo '<tr><td class="strong">' . e((string) $f['original_name'])
                    . ($f['rel_path'] !== '' ? '<div class="muted small">' . e((string) $f['rel_path']) . '/</div>' : '') . '</td>'
                    . '<td class="muted">' . e((string) $f['mime_type']) . '</td><td>' . e(formatBytes((int) $f['file_size'])) . '</td>'
                    . '<td><a class="btn btn-primary" href="' . e(selfUrl(['f' => (string) $f['id']])) . '">&#11015; Download</a></td></tr>';
            }
            echo '</tbody></table></div></div>';
        }
        if (!$files) {
            echo '<p class="muted center">No files in this project yet.</p>';
        } elseif ($total > count($files)) {
            echo '<p class="muted small center">Showing the first ' . count($files) . ' of ' . $total . ' files.</p>';
        }
        publicFooter();
        pageEnd();
        exit;
    }

    $imgs = "'" . implode("','", SAFE_IMAGE_MIMES) . "'";
    $rows = $pdo->query("SELECT f.id, f.folder_name, f.description, COUNT(fl.id) AS file_count,
            (SELECT c.id FROM files c WHERE c.folder_id = f.id AND c.mime_type IN ($imgs)
                AND c.file_size BETWEEN 1 AND " . PREVIEW_MAX_BYTES . " ORDER BY c.id LIMIT 1) AS cover_id
        FROM folders f LEFT JOIN files fl ON fl.folder_id = f.id
        WHERE f.is_public = 1 GROUP BY f.id, f.folder_name, f.description ORDER BY f.created_at DESC, f.id DESC")->fetchAll();

    pageStart($center . ' - ' . (string) config('center_tagline'));
    publicHeader();
    echo '<h2 class="section-title">Student Projects (' . count($rows) . ')</h2>';
    if (!$rows) {
        echo '<p class="muted center">Projects will appear here soon.</p>';
    } else {
        echo '<div class="project-grid">';
        foreach ($rows as $r) {
            echo '<a class="project-card" href="' . e(selfUrl(['p' => (string) $r['id']])) . '"><div class="cover">'
                . ($r['cover_id'] !== null
                    ? '<img loading="lazy" src="' . e(selfUrl(['v' => (string) $r['cover_id']])) . '" alt="">'
                    : '&#128193;')
                . '</div><div class="pc-body"><h3>' . e((string) $r['folder_name']) . '</h3>'
                . ($r['description'] !== '' ? '<p class="muted small">' . e(shorten((string) $r['description'], 110)) . '</p>' : '')
                . '<span class="badge">' . (int) $r['file_count'] . ' files</span></div></a>';
        }
        echo '</div>';
    }
    publicFooter();
    pageEnd();
    exit;
}

// ============================================================================
// 8. VIEWS
// ============================================================================
function cssBlock(): string
{
    return <<<'CSS'
:root{--bg:#0f172a;--surface:#1e293b;--border:#334155;--text:#f8fafc;--muted:#94a3b8;--primary:#38bdf8;--primary-dark:#0284c7;--danger:#ef4444;--radius:12px}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;line-height:1.5}
.container{max-width:1140px;margin:0 auto;padding:28px 20px}
header{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:16px;padding-bottom:22px;border-bottom:1px solid var(--border);margin-bottom:24px}
.brand{display:flex;align-items:center;gap:12px}.brand.mb{margin-bottom:20px}
.brand-badge{background:linear-gradient(135deg,var(--primary),var(--primary-dark));color:#0f172a;font-weight:800;padding:8px 12px;border-radius:10px;font-size:1.1rem}
.brand h1{font-size:1.35rem;font-weight:700}.brand p{font-size:.85rem;color:var(--muted)}
.nav-tabs{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:24px}
.tab-btn{text-decoration:none;padding:11px 20px;border-radius:var(--radius);font-weight:600;font-size:.95rem;background:var(--surface);color:var(--muted);border:1px solid var(--border)}
.tab-btn:hover{color:var(--text);border-color:var(--primary)}.tab-btn.active{background:var(--primary);color:#0f172a;border-color:var(--primary)}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:26px}
.stat-card{background:var(--surface);border:1px solid var(--border);padding:20px;border-radius:var(--radius)}
.stat-card span{font-size:.8rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
.stat-card strong{display:block;font-size:1.8rem;margin-top:6px;color:var(--primary)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:24px;margin-bottom:24px}
.card h2{font-size:1.15rem;margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.grid-2{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:24px}
.form-group{margin-bottom:16px}
label{display:block;font-size:.9rem;font-weight:600;margin-bottom:6px;color:#cbd5e1}
input[type=text],input[type=password],input[type=file],select{width:100%;padding:11px 14px;background:#0f172a;border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:.95rem}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 18px;border-radius:8px;font-weight:600;font-size:.9rem;cursor:pointer;border:none;text-decoration:none}
.btn:hover{opacity:.9}.btn.full{width:100%}
.btn-primary{background:var(--primary);color:#0f172a}
.btn-danger{background:rgba(239,68,68,.15);color:#fca5a5;border:1px solid rgba(239,68,68,.35)}
.btn-outline{background:transparent;color:var(--text);border:1px solid var(--border)}
.alert{padding:14px 18px;border-radius:var(--radius);margin-bottom:20px;font-weight:500}
.alert-success{background:rgba(34,197,94,.15);border:1px solid rgba(34,197,94,.4);color:#86efac}
.alert-error{background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.4);color:#fca5a5}
.alert-warning{background:rgba(234,179,8,.15);border:1px solid rgba(234,179,8,.4);color:#fde047}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.92rem}
th,td{text-align:left;padding:12px 14px;border-bottom:1px solid var(--border)}
th{color:var(--muted);font-weight:600;font-size:.8rem;text-transform:uppercase}
.badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:.78rem;background:rgba(56,189,248,.15);color:var(--primary)}
.filter-bar{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:18px}
.filter-bar input,.filter-bar select{width:auto;min-width:200px;flex:1}
.login-box{max-width:440px;margin:70px auto}
.actions-cell{display:flex;gap:8px;align-items:center}
.muted{color:var(--muted)}.small{font-size:.8rem}.strong{font-weight:600}.link{color:var(--primary);text-decoration:none;font-weight:600}
.hint{font-size:.8rem;color:var(--muted);margin-top:6px}.hint.warn{color:#fde047}
.hero{text-align:center;padding:26px 0 22px;border-bottom:1px solid var(--border);margin-bottom:26px}
.hero h1{font-size:2rem}.hero p{color:var(--muted)}.center-brand{justify-content:center;margin-bottom:8px}
.section-title{font-size:1.25rem;margin-bottom:16px}
.project-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:20px}
.project-card{display:block;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;text-decoration:none;color:var(--text)}
.project-card:hover{border-color:var(--primary)}
.cover{height:170px;background:#0f172a;display:flex;align-items:center;justify-content:center;font-size:3rem}
.cover img{width:100%;height:100%;object-fit:cover}
.pc-body{padding:16px}.pc-body h3{font-size:1.05rem;margin-bottom:6px}.pc-body p{margin-bottom:10px}
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:16px}
.gallery figure{background:#0f172a;border:1px solid var(--border);border-radius:10px;overflow:hidden}
.gallery img{display:block;width:100%;height:180px;object-fit:cover}
.gallery figcaption{padding:10px 12px;font-size:.82rem;display:flex;justify-content:space-between;gap:8px;word-break:break-word}
.back{display:inline-block;margin-bottom:16px}.desc{margin-bottom:12px}
.center{text-align:center}.footer{margin-top:30px}
textarea{width:100%;padding:11px 14px;background:#0f172a;border:1px solid var(--border);border-radius:8px;color:var(--text);font-size:.95rem;font-family:inherit;min-height:80px}
.checkrow{display:flex;gap:8px;align-items:center;margin-bottom:16px}.checkrow label{margin:0}
details.edit summary{cursor:pointer;list-style:none}details.edit form{margin-top:10px;min-width:260px}
.pager{display:flex;flex-wrap:wrap;gap:8px;margin-top:18px;align-items:center}
code{background:#0f172a;padding:2px 6px;border-radius:6px;word-break:break-all}
CSS;
}

function pageStart(string $title, ?array $flash = null): void
{
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        . '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        . (!empty($GLOBALS['cv_indexable']) ? '' : '<meta name="robots" content="noindex,nofollow">') . '<meta name="referrer" content="no-referrer">'
        . '<title>' . e($title) . '</title><style nonce="' . nonce() . '">' . cssBlock() . '</style></head>'
        . '<body><div class="container">';
    if ($flash) {
        $t = in_array($flash['type'], ['success', 'error', 'warning'], true) ? $flash['type'] : 'error';
        echo '<div class="alert alert-' . $t . '" role="alert">' . e((string) $flash['msg']) . '</div>';
    }
}

function pageEnd(): void
{
    echo '</div><script nonce="' . nonce() . '">' . <<<'JS'
document.addEventListener('click',function(ev){var b=ev.target.closest('[data-copy]');if(!b){return;}var u=new URL(b.getAttribute('data-copy'),window.location.href).href,t=b.textContent;
  var done=function(){b.textContent='Copied!';setTimeout(function(){b.textContent=t;},1500);};
  if(navigator.clipboard){navigator.clipboard.writeText(u).then(done,function(){window.prompt('Copy this link:',u);});}else{window.prompt('Copy this link:',u);}});
document.addEventListener('submit',function(ev){var m=ev.target.getAttribute('data-confirm');if(m&&!window.confirm(m)){ev.preventDefault();}});
function fmt(b){var u=['B','KB','MB','GB'],i=0;while(b>=1024&&i<3){b/=1024;i++;}return b.toFixed(i?1:0)+' '+u[i];}
document.querySelectorAll('input[type=file][data-summary]').forEach(function(inp){
  inp.addEventListener('change',function(){
    var out=document.getElementById(inp.getAttribute('data-summary')),n=inp.files.length,t=0,big=0,i;
    var maxFile=+inp.getAttribute('data-max-file'),maxPost=+inp.getAttribute('data-max-post'),maxCount=+inp.getAttribute('data-max-count');
    for(i=0;i<n;i++){t+=inp.files[i].size;if(inp.files[i].size>maxFile){big++;}}
    var msg=n+' file(s) selected, '+fmt(t),warn='';
    if(maxCount&&n>maxCount){warn+=' PHP max_file_uploads is '+maxCount+' - extra files will be dropped.';}
    if(maxPost&&t>maxPost){warn+=' Total exceeds post_max_size ('+fmt(maxPost)+').';}
    if(big){warn+=' '+big+' file(s) exceed the per-file limit of '+fmt(maxFile)+'.';}
    out.textContent=msg+warn;out.className='hint'+(warn?' warn':'');
  });
});
JS
        . '</script></body></html>';
}

function renderConfigError(): never
{
    $suggest = base64_encode(random_bytes(32));
    fatalPage(500, 'Configuration required',
        '<p class="muted">Set a valid <code>app_key</code> (base64 of 32 random bytes). This key encrypts every file stored in MySQL - '
        . 'back it up; without it files cannot be decrypted.</p>'
        . '<p class="hint">Example freshly generated key (put it in <code>CV_APP_KEY</code> or the config block):</p>'
        . '<p><code>' . e($suggest) . '</code></p>');
}

function renderSetup(bool $hasSetupKey): void
{
    pageStart('VasmuVault - First-time setup', pullFlash());
    echo '<div class="card login-box"><div class="brand mb"><div class="brand-badge">CV</div><div><h1>First-time setup</h1>'
        . '<p>Create the admin account</p></div></div>';
    if (!$hasSetupKey) {
        echo '<p class="muted">Set <code>setup_key</code> (a long random secret) in the config or <code>CV_SETUP_KEY</code> env var, then reload this page.</p></div>';
        pageEnd();
        return;
    }
    echo '<form method="POST" action="' . e(selfUrl()) . '" autocomplete="off">'
        . '<input type="hidden" name="form_action" value="setup">' . csrfField()
        . '<div class="form-group"><label for="setup_key">Setup key</label><input type="password" id="setup_key" name="setup_key" required></div>'
        . '<div class="form-group"><label for="username">Admin username</label><input type="text" id="username" name="username" required minlength="3" maxlength="64"></div>'
        . '<div class="form-group"><label for="password">Password (min 12 characters)</label><input type="password" id="password" name="password" required minlength="12" autocomplete="new-password"></div>'
        . '<div class="form-group"><label for="password2">Confirm password</label><input type="password" id="password2" name="password2" required minlength="12" autocomplete="new-password"></div>'
        . '<button type="submit" class="btn btn-primary full">Create admin</button></form></div>';
    pageEnd();
}

function renderLogin(): void
{
    pageStart('VasmuVault - Admin Login', pullFlash());
    echo '<div class="card login-box"><div class="brand mb"><div class="brand-badge">CV</div><div><h1>VasmuVault Admin</h1>'
        . '<p>Login to upload &amp; download files</p></div></div>'
        . '<form method="POST" action="' . e(selfUrl()) . '">'
        . '<input type="hidden" name="form_action" value="login">' . csrfField()
        . '<div class="form-group"><label for="username">Admin username</label><input type="text" id="username" name="username" required autofocus maxlength="64" autocomplete="username"></div>'
        . '<div class="form-group"><label for="password">Admin password</label><input type="password" id="password" name="password" required autocomplete="current-password"></div>'
        . '<button type="submit" class="btn btn-primary full">Login</button></form></div>';
    pageEnd();
}

function renderDashboard(PDO $pdo): void
{
    $tab    = ($_GET['tab'] ?? 'browse') === 'upload' ? 'upload' : 'browse';
    $folder = is_string($_GET['folder'] ?? null) ? $_GET['folder'] : 'all';
    if ($folder !== 'all' && $folder !== 'root' && !ctype_digit($folder)) {
        $folder = 'all';
    }
    $q    = substr(trim(is_string($_GET['q'] ?? null) ? $_GET['q'] : ''), 0, 100);
    $page = max(1, (int) (is_string($_GET['page'] ?? null) ? $_GET['page'] : 1));

    $stats        = $pdo->query('SELECT COUNT(*) AS c, COALESCE(SUM(file_size),0) AS b FROM files')->fetch();
    $totalFiles   = (int) $stats['c'];
    $totalBytes   = (int) $stats['b'];
    $totalFolders = (int) $pdo->query('SELECT COUNT(*) FROM folders')->fetchColumn();
    $folders      = $pdo->query('SELECT f.id, f.folder_name, f.description, f.is_public, f.created_at, COUNT(fl.id) AS file_count,
                                        COALESCE(SUM(fl.file_size),0) AS folder_bytes
                                 FROM folders f LEFT JOIN files fl ON fl.folder_id = f.id
                                 GROUP BY f.id, f.folder_name, f.description, f.is_public, f.created_at ORDER BY f.folder_name')->fetchAll();

    pageStart('VasmuVault - Admin Portal', pullFlash());
    echo '<header><div class="brand"><div class="brand-badge">CV</div><div><h1>VasmuVault MySQL Storage</h1>'
        . '<p>Logged in as <strong>' . e((string) $_SESSION['admin_user']) . '</strong> &bull; PHP ' . e(PHP_VERSION)
        . ' &bull; Encrypted at rest</p></div></div>'
        . '<form method="POST" action="' . e(selfUrl()) . '"><input type="hidden" name="form_action" value="logout">' . csrfField()
        . '<button type="submit" class="btn btn-outline">Logout</button></form></header>';

    echo '<div class="stats-grid">'
        . '<div class="stat-card"><span>Total Uploaded Files</span><strong>' . number_format($totalFiles) . '</strong></div>'
        . '<div class="stat-card"><span>Total Folders</span><strong>' . number_format($totalFolders) . '</strong></div>'
        . '<div class="stat-card"><span>MySQL Storage Used</span><strong>' . e(formatBytes($totalBytes)) . '</strong></div></div>';

    echo '<nav class="nav-tabs"><a href="' . e(selfUrl(['tab' => 'upload'])) . '" class="tab-btn' . ($tab === 'upload' ? ' active' : '') . '">1. Upload File &amp; Create Folder</a>'
        . '<a href="' . e(selfUrl(['tab' => 'browse'])) . '" class="tab-btn' . ($tab === 'browse' ? ' active' : '') . '">2. View Files &amp; Folders (' . $totalFiles . ' Files / ' . $totalFolders . ' Folders)</a></nav>';

    if ($tab === 'upload') {
        $maxFile  = maxFileBytes();
        $maxPost  = min(iniBytes((string) ini_get('post_max_size')), PHP_INT_MAX);
        $maxCount = (int) ini_get('max_file_uploads');
        $limits   = ' data-max-file="' . $maxFile . '" data-max-post="' . ($maxPost === PHP_INT_MAX ? 0 : $maxPost) . '" data-max-count="' . $maxCount . '"';

        echo '<div class="grid-2">';
        echo '<div class="card"><h2>Upload Files</h2><form method="POST" action="' . e(selfUrl(['tab' => 'upload'])) . '" enctype="multipart/form-data">'
            . '<input type="hidden" name="form_action" value="upload_files">' . csrfField()
            . '<div class="form-group"><label for="folder_id">Destination folder (optional)</label><select name="folder_id" id="folder_id"><option value="">-- Root (No Folder) --</option>';
        foreach ($folders as $f) {
            echo '<option value="' . (int) $f['id'] . '">' . e((string) $f['folder_name']) . ' (' . (int) $f['file_count'] . ' files)</option>';
        }
        echo '</select></div><div class="form-group"><label for="files">Choose file(s) - max ' . e(formatBytes($maxFile)) . ' each</label>'
            . '<input type="file" name="files[]" id="files" multiple required data-summary="sum1"' . $limits . '><div id="sum1" class="hint"></div></div>'
            . '<button type="submit" class="btn btn-primary">Upload &amp; Encrypt in MySQL</button></form></div>';

        echo '<div class="card"><h2>Upload an Entire Folder</h2><form method="POST" action="' . e(selfUrl(['tab' => 'upload'])) . '" enctype="multipart/form-data">'
            . '<input type="hidden" name="form_action" value="upload_folder">' . csrfField()
            . '<div class="form-group"><label for="dir">Choose a folder from your device</label>'
            . '<input type="file" name="dir[]" id="dir" webkitdirectory multiple required data-summary="sum2"' . $limits . '>'
            . '<div id="sum2" class="hint">A folder with the same name is created automatically; sub-folder paths are kept.</div></div>'
            . '<button type="submit" class="btn btn-primary">Upload Folder</button></form></div>';

        echo '<div class="card"><h2>Create a New Folder / Project</h2><form method="POST" action="' . e(selfUrl(['tab' => 'upload'])) . '">'
            . '<input type="hidden" name="form_action" value="create_folder">' . csrfField()
            . '<div class="form-group"><label for="folder_name">Folder / project name</label><input type="text" name="folder_name" id="folder_name" required maxlength="190" placeholder="e.g. Rahul Sharma - Billing Software"></div>'
            . '<div class="form-group"><label for="description">Short description (shown on the portfolio)</label><textarea name="description" id="description" maxlength="500" placeholder="e.g. Tally + MS Excel project made during ADCA course"></textarea></div>'
            . '<div class="checkrow"><input type="checkbox" name="is_public" id="is_public" value="1"><label for="is_public">Show publicly on the portfolio website</label></div>'
            . '<button type="submit" class="btn btn-primary">Create</button></form></div></div>';
        pageEnd();
        return;
    }

    // ---- Browse tab ----
    echo '<div class="card"><h2>Share your portfolio</h2><p class="muted desc">Give this link to clients. It shows only the folders marked <strong>Public</strong>; everything else stays private.</p>'
        . '<button type="button" class="btn btn-primary" data-copy="' . e(selfUrl()) . '">Copy portfolio link</button> '
        . '<a class="btn btn-outline" href="' . e(selfUrl()) . '" target="_blank" rel="noopener">Preview</a></div>';
    echo '<div class="card"><h2>Folders (' . count($folders) . ')</h2>';
    if (!$folders) {
        echo '<p class="muted">No folders yet. Create one from the Upload tab.</p>';
    } else {
        echo '<div class="table-wrap"><table><thead><tr><th>Folder</th><th>Visibility</th><th>Files</th><th>Total size</th><th>Actions</th></tr></thead><tbody>';
        foreach ($folders as $f) {
            $u = e(selfUrl(['tab' => 'browse', 'folder' => (string) $f['id']]));
            $pub = (int) $f['is_public'] === 1;
            echo '<tr><td><a class="link" href="' . $u . '">&#128193; ' . e((string) $f['folder_name']) . '</a>'
                . ($f['description'] !== '' ? '<div class="muted small">' . e(shorten((string) $f['description'], 80)) . '</div>' : '') . '</td>'
                . '<td><span class="badge">' . ($pub ? 'Public' : 'Private') . '</span></td>'
                . '<td><span class="badge">' . (int) $f['file_count'] . ' files</span></td>'
                . '<td>' . e(formatBytes((int) $f['folder_bytes'])) . '</td>'
                . '<td class="actions-cell"><a class="btn btn-outline" href="' . $u . '">Open</a>'
                . ($pub ? '<button type="button" class="btn btn-outline" data-copy="' . e(selfUrl(['p' => (string) $f['id']])) . '">Copy link</button>' : '')
                . '<details class="edit"><summary class="btn btn-outline">Edit</summary>'
                . '<form method="POST" action="' . e(selfUrl(['tab' => 'browse'])) . '"><input type="hidden" name="form_action" value="update_folder">' . csrfField()
                . '<input type="hidden" name="folder_id" value="' . (int) $f['id'] . '">'
                . '<div class="form-group"><label>Name</label><input type="text" name="folder_name" required maxlength="190" value="' . e((string) $f['folder_name']) . '"></div>'
                . '<div class="form-group"><label>Description</label><textarea name="description" maxlength="500">' . e((string) $f['description']) . '</textarea></div>'
                . '<div class="checkrow"><input type="checkbox" name="is_public" value="1"' . ($pub ? ' checked' : '') . '><label>Public on portfolio</label></div>'
                . '<button type="submit" class="btn btn-primary">Save</button></form></details>'
                . '<form method="POST" action="' . e(selfUrl(['tab' => 'browse'])) . '" data-confirm="Delete this folder? Its files will move to Root (and become private).">'
                . '<input type="hidden" name="form_action" value="delete_folder">' . csrfField() . '<input type="hidden" name="folder_id" value="' . (int) $f['id'] . '">'
                . '<button type="submit" class="btn btn-danger">Delete</button></form></td></tr>';
        }
        echo '</tbody></table></div>';
    }
    echo '</div>';

    $where  = ' WHERE 1=1';
    $params = [];
    if ($folder === 'root') {
        $where .= ' AND fl.folder_id IS NULL';
    } elseif ($folder !== 'all') {
        $where .= ' AND fl.folder_id = ?';
        $params[] = (int) $folder;
    }
    if ($q !== '') {
        $where .= " AND fl.original_name LIKE ? ESCAPE '|'";
        $params[] = '%' . str_replace(['|', '%', '_'], ['||', '|%', '|_'], $q) . '%';
    }
    $cnt = $pdo->prepare('SELECT COUNT(*) FROM files fl' . $where);
    $cnt->execute($params);
    $matched = (int) $cnt->fetchColumn();
    $pages   = max(1, (int) ceil($matched / PER_PAGE));
    $page    = min($page, $pages);

    $st = $pdo->prepare('SELECT fl.id, fl.original_name, fl.rel_path, fl.mime_type, fl.file_size, fl.sha256, fl.uploaded_at, fd.folder_name
                         FROM files fl LEFT JOIN folders fd ON fd.id = fl.folder_id' . $where
                         . ' ORDER BY fl.uploaded_at DESC, fl.id DESC LIMIT ' . PER_PAGE . ' OFFSET ' . (($page - 1) * PER_PAGE));
    $st->execute($params);
    $files = $st->fetchAll();

    echo '<div class="card"><h2>Files (' . $matched . ' match)</h2>'
        . '<form method="GET" action="' . e(selfUrl()) . '" class="filter-bar"><input type="hidden" name="tab" value="browse">'
        . '<select name="folder" aria-label="Folder"><option value="all"' . ($folder === 'all' ? ' selected' : '') . '>All folders (' . $totalFiles . ')</option>'
        . '<option value="root"' . ($folder === 'root' ? ' selected' : '') . '>Root / uncategorized</option>';
    foreach ($folders as $f) {
        echo '<option value="' . (int) $f['id'] . '"' . ($folder === (string) $f['id'] ? ' selected' : '') . '>' . e((string) $f['folder_name']) . ' (' . (int) $f['file_count'] . ')</option>';
    }
    echo '</select><input type="text" name="q" value="' . e($q) . '" maxlength="100" placeholder="Search by file name..." aria-label="Search">'
        . '<button type="submit" class="btn btn-primary">Filter</button>';
    if ($folder !== 'all' || $q !== '') {
        echo '<a class="btn btn-outline" href="' . e(selfUrl(['tab' => 'browse'])) . '">Reset</a>';
    }
    echo '</form>';

    if (!$files) {
        echo '<p class="muted">No files found.</p>';
    } else {
        echo '<div class="table-wrap"><table><thead><tr><th>File</th><th>Folder</th><th>Type</th><th>Size</th><th>SHA-256</th><th>Uploaded</th><th>Download / Delete</th></tr></thead><tbody>';
        foreach ($files as $f) {
            echo '<tr><td class="strong">' . e((string) $f['original_name'])
                . ($f['rel_path'] !== '' ? '<div class="muted small">' . e((string) $f['rel_path']) . '/</div>' : '') . '</td>'
                . '<td><span class="badge">' . ($f['folder_name'] !== null ? '&#128193; ' . e((string) $f['folder_name']) : 'Root') . '</span></td>'
                . '<td class="muted">' . e((string) $f['mime_type']) . '</td><td>' . e(formatBytes((int) $f['file_size'])) . '</td>'
                . '<td class="muted small"><code>' . e(substr((string) $f['sha256'], 0, 12)) . '&hellip;</code></td>'
                . '<td>' . e((string) $f['uploaded_at']) . '</td><td class="actions-cell">'
                . '<a class="btn btn-primary" href="' . e(selfUrl(['download' => (string) $f['id']])) . '">&#11015; Download</a>'
                . '<form method="POST" action="' . e(selfUrl(['tab' => 'browse'])) . '" data-confirm="Permanently delete this file?">'
                . '<input type="hidden" name="form_action" value="delete_file">' . csrfField() . '<input type="hidden" name="file_id" value="' . (int) $f['id'] . '">'
                . '<button type="submit" class="btn btn-danger">Delete</button></form></td></tr>';
        }
        echo '</tbody></table></div>';
        if ($pages > 1) {
            echo '<div class="pager">';
            $base = ['tab' => 'browse', 'folder' => $folder, 'q' => $q];
            if ($page > 1) {
                echo '<a class="btn btn-outline" href="' . e(selfUrl($base + ['page' => $page - 1])) . '">&laquo; Prev</a>';
            }
            echo '<span class="muted">Page ' . $page . ' / ' . $pages . '</span>';
            if ($page < $pages) {
                echo '<a class="btn btn-outline" href="' . e(selfUrl($base + ['page' => $page + 1])) . '">Next &raquo;</a>';
            }
            echo '</div>';
        }
    }
    echo '</div>';

    $log = $pdo->query('SELECT admin_username, action, detail, ip, created_at FROM audit_log ORDER BY id DESC LIMIT 8')->fetchAll();
    echo '<div class="card"><h2>Recent security activity</h2>';
    if (!$log) {
        echo '<p class="muted">No activity yet.</p>';
    } else {
        echo '<div class="table-wrap"><table><thead><tr><th>Time</th><th>User</th><th>Action</th><th>Detail</th><th>IP</th></tr></thead><tbody>';
        foreach ($log as $l) {
            echo '<tr><td>' . e((string) $l['created_at']) . '</td><td>' . e((string) $l['admin_username']) . '</td><td><span class="badge">'
                . e((string) $l['action']) . '</span></td><td class="muted">' . e((string) $l['detail']) . '</td><td class="muted">' . e((string) $l['ip']) . '</td></tr>';
        }
        echo '</tbody></table></div>';
    }
    echo '</div>';
    pageEnd();
}

// ============================================================================
// 9. FRONT CONTROLLER
// ============================================================================
sendSecurityHeaders();

if (config('require_https') && !isHttps() && !isLoopback()) {
    fatalPage(403, 'HTTPS required', '<p class="muted">Please open this page over HTTPS. Credentials and files must never travel over plain HTTP.</p>'
        . '<p class="hint">Already on https:// but still seeing this? Your host sits behind a proxy: set <code>trust_proxy</code> to true in the config.</p>');
}

if (appKey() === null) {
    renderConfigError();
}

$pdo = db();

$isAdminRequest = $_SERVER['REQUEST_METHOD'] === 'POST'
    || isset($_GET['admin']) || isset($_GET['tab']) || isset($_GET['download']);

if ((int) $pdo->query('SELECT COUNT(*) FROM admins')->fetchColumn() === 0) {
    startSession();
    handleSetup($pdo);
}

if (!$isAdminRequest) {
    renderPublic($pdo); // public portfolio: no session, no cookie
}

startSession();

if (!sessionIsValid()) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['form_action'] ?? '') === 'login') {
        handleLogin($pdo);
    }
    renderLogin();
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    handlePost($pdo);
}

if (isset($_GET['download'])) {
    $dl = filter_var($_GET['download'], FILTER_VALIDATE_INT);
    if ($dl === false || $dl < 1) {
        flash('error', 'Invalid file id.');
        redirect(selfUrl(['tab' => 'browse']));
    }
    handleDownload($pdo, $dl);
}

renderDashboard($pdo);
