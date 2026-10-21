<?php
declare(strict_types=1);

/*
 * Single-file secure pastebin
 *
 * Requirements:
 * - PHP 8.0+
 * - pdo_sqlite
 * - sodium
 * - mbstring
 *
 * Security model:
 * - Non-password pastes are encrypted with a server master key.
 * - Password pastes are encrypted with a key derived from the user password.
 *   The server does not store the password and cannot recover it.
 * - Paste links are random capability URLs.
 * - Expired pastes are deleted lazily and by CLI cleanup.
 */

const MAX_CONTENT_BYTES = 1024 * 1024; // 1 MiB
const MIN_PASSWORD_LENGTH = 8;
const SLUG_BYTES = 18;
const DEFAULT_EXPIRE_KEY = '1d';

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

/*
 * Configuration via environment variables.
 *
 * Recommended production values:
 *
 *   PASTEBIN_DATA_DIR=/var/lib/pastebin
 *   PASTEBIN_MASTER_KEY=<base64-encoded 32-byte key>
 *
 * If PASTEBIN_MASTER_KEY is not set, the app will create/use:
 *   PASTEBIN_DATA_DIR/secret.key
 */
$DATA_DIR = getenv('PASTEBIN_DATA_DIR');
if (!is_string($DATA_DIR) || $DATA_DIR === '') {
    $DATA_DIR = __DIR__ . '/data';
}

$DB_FILE = getenv('PASTEBIN_DB_FILE');
if (!is_string($DB_FILE) || $DB_FILE === '') {
    $DB_FILE = $DATA_DIR . '/pastebin.sqlite';
}

$KEY_FILE = getenv('PASTEBIN_KEY_FILE');
if (!is_string($KEY_FILE) || $KEY_FILE === '') {
    $KEY_FILE = $DATA_DIR . '/secret.key';
}

$MASTER_KEY_ENV = getenv('PASTEBIN_MASTER_KEY');

$EXPIRE_OPTIONS = [
    '10m'   => ['seconds' => 600,      'label' => '10 minutes'],
    '1h'    => ['seconds' => 3600,     'label' => '1 hour'],
    '6h'    => ['seconds' => 21600,    'label' => '6 hours'],
    '1d'    => ['seconds' => 86400,    'label' => '1 day'],
    '7d'    => ['seconds' => 604800,   'label' => '7 days'],
    '30d'   => ['seconds' => 2592000,  'label' => '30 days'],
    'never' => ['seconds' => null,     'label' => 'Never'],
];

if (!extension_loaded('sodium')) {
    http_response_code(500);
    exit('PHP extension required: sodium');
}

if (!extension_loaded('pdo_sqlite')) {
    http_response_code(500);
    exit('PHP extension required: pdo_sqlite');
}

if (!function_exists('mb_check_encoding')) {
    http_response_code(500);
    exit('PHP extension required: mbstring');
}

define('KEY_BYTES', SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
define('NONCE_BYTES', SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
define('SALT_BYTES', SODIUM_CRYPTO_PWHASH_SALTBYTES);

function protect_directory(string $dir): void
{
    $dir = rtrim($dir, "/\\");
    if ($dir === '') {
        return;
    }

    $htaccess = $dir . DIRECTORY_SEPARATOR . '.htaccess';
    if (!file_exists($htaccess)) {
        $contents = "<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n"
            . "<IfModule !mod_authz_core.c>\n  Order deny,allow\n  Deny from all\n</IfModule>\n";
        @file_put_contents($htaccess, $contents);
    }

    $index = $dir . DIRECTORY_SEPARATOR . 'index.html';
    if (!file_exists($index)) {
        @file_put_contents($index, '');
    }
}

function data_dir_is_public(string $dir): bool
{
    if (PHP_SAPI === 'cli') {
        return false;
    }

    $docRoot = $_SERVER['DOCUMENT_ROOT'] ?? '';
    if (!is_string($docRoot) || $docRoot === '') {
        return false;
    }

    $realDoc = realpath($docRoot);
    $realDir = realpath($dir);

    if ($realDoc === false || $realDir === false) {
        return false;
    }

    $realDoc = rtrim($realDoc, "/\\");
    $realDir = rtrim($realDir, "/\\");

    if ($realDoc === '' || $realDir === '') {
        return false;
    }

    return $realDir === $realDoc
        || str_starts_with($realDir . DIRECTORY_SEPARATOR, $realDoc . DIRECTORY_SEPARATOR);
}

if (!is_dir($DATA_DIR)) {
    if (!mkdir($DATA_DIR, 0700, true) && !is_dir($DATA_DIR)) {
        http_response_code(500);
        exit('Cannot create data directory.');
    }
}

protect_directory($DATA_DIR);

/*
 * By default, refuse to run if the data directory is inside the web root.
 *
 * For local testing only, you may set:
 *   PASTEBIN_ALLOW_INSECURE_DATADIR=1
 */
if (data_dir_is_public($DATA_DIR) && getenv('PASTEBIN_ALLOW_INSECURE_DATADIR') == '1') {
    http_response_code(500);
    exit(
        'Secure configuration required: set PASTEBIN_DATA_DIR outside the document root, '
        . 'or set PASTEBIN_ALLOW_INSECURE_DATADIR=1 for testing.'
    );
}

function normalize_key_material(string $material): ?string
{
    if (strlen($material) === 32) {
        return $material;
    }

    $trimmed = trim($material);

    $base64 = base64_decode($trimmed, true);
    if (is_string($base64) && strlen($base64) === 32) {
        return $base64;
    }

    $hex = @hex2bin($trimmed);
    if (is_string($hex) && strlen($hex) === 32) {
        return $hex;
    }

    return null;
}

function load_master_key(): string
{
    global $MASTER_KEY_ENV, $KEY_FILE;

    if (is_string($MASTER_KEY_ENV) && $MASTER_KEY_ENV !== '') {
        $key = normalize_key_material($MASTER_KEY_ENV);
        if ($key === null) {
            http_response_code(500);
            exit('PASTEBIN_MASTER_KEY must contain/base64/hex encode exactly 32 bytes.');
        }
        return $key;
    }

    if (is_readable($KEY_FILE)) {
        $raw = file_get_contents($KEY_FILE);
        if ($raw === false) {
            http_response_code(500);
            exit('Cannot read key file.');
        }

        $key = normalize_key_material($raw);
        if ($key === null) {
            http_response_code(500);
            exit('Key file must contain 32 raw bytes or base64/hex encoded 32 bytes.');
        }

        return $key;
    }

    $key = random_bytes(32);
    $dir = dirname($KEY_FILE);

    if (!is_dir($dir)) {
        if (!mkdir($dir, 0700, true) && !is_dir($dir)) {
            http_response_code(500);
            exit('Cannot create key directory.');
        }
    }

    if (file_put_contents($KEY_FILE, $key, LOCK_EX) === false) {
        http_response_code(500);
        exit('Cannot write key file.');
    }

    @chmod($KEY_FILE, 0600);

    return $key;
}

$MASTER_KEY = load_master_key();

function e(?string $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }

    return $_SESSION['csrf'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf" value="' . e(csrf_token()) . '">';
}

function is_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
        return true;
    }

    /*
     * Only trust this if you are behind a properly configured reverse proxy
     * that strips/overwrites X-Forwarded-Proto.
     */
    if (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https') {
        return true;
    }

    if ((int) ($_SERVER['SERVER_PORT'] ?? 0) === 443) {
        return true;
    }

    return false;
}

function start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $secure = is_https();

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    ini_set('session.use_strict_mode', '1');
    ini_set('session.sid_length', '48');
    ini_set('session.sid_bits_per_character', '6');

    session_name('pb_session');
    @session_start();

    if (!isset($_SESSION) || !is_array($_SESSION)) {
        $_SESSION = [];
    }

    if (empty($_SESSION['csrf']) || !is_string($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
}

function send_security_headers(): void
{
    header(
        'Content-Security-Policy: default-src \'self\'; '
        . 'style-src \'self\' \'unsafe-inline\'; '
        . 'script-src \'none\'; '
        . 'object-src \'none\'; '
        . 'base-uri \'none\'; '
        . 'form-action \'self\'; '
        . 'frame-ancestors \'none\''
    );
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
}

function db(): PDO
{
    global $DB_FILE;

    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dir = dirname($DB_FILE);
    if (!is_dir($dir)) {
        if (!mkdir($dir, 0700, true) && !is_dir($dir)) {
            http_response_code(500);
            exit('Cannot create database directory.');
        }
    }

    $isNew = !file_exists($DB_FILE);

    $pdo = new PDO('sqlite:' . $DB_FILE, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);

    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA synchronous=NORMAL');
    $pdo->exec('PRAGMA busy_timeout=5000');
    $pdo->exec('PRAGMA foreign_keys=ON');

    if ($isNew) {
        @chmod($DB_FILE, 0600);
    }

    $pdo->exec('CREATE TABLE IF NOT EXISTS pastes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        slug TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NULL,
        has_password INTEGER NOT NULL DEFAULT 0,
        kdf_salt BLOB NULL,
        nonce BLOB NOT NULL,
        ciphertext BLOB NOT NULL,
        size_bytes INTEGER NOT NULL
    )');

    $pdo->exec('CREATE INDEX IF NOT EXISTS idx_pastes_expires ON pastes(expires_at)');

    $pdo->exec('CREATE TABLE IF NOT EXISTS rate_limits (
        bucket TEXT PRIMARY KEY,
        window_start INTEGER NOT NULL,
        hit_count INTEGER NOT NULL
    )');

    return $pdo;
}

function b64url_encode(string $binary): string
{
    return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
}

function generate_slug(): string
{
    return b64url_encode(random_bytes(SLUG_BYTES));
}

function is_valid_slug(string $slug): bool
{
    return (bool) preg_match('/^[A-Za-z0-9_-]{8,32}$/', $slug);
}

function derive_password_key(string $password, string $salt): string
{
    return sodium_crypto_pwhash(
        KEY_BYTES,
        $password,
        $salt,
        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
    );
}

function encrypt_message(string $plaintext, string $key): array
{
    $nonce = random_bytes(NONCE_BYTES);
    $ciphertext = sodium_crypto_secretbox($plaintext, $nonce, $key);

    return [$nonce, $ciphertext];
}

function decrypt_message(string $ciphertext, string $nonce, string $key): string|false
{
    return sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
}

function binary_value(mixed $value): string
{
    if (is_resource($value)) {
        $data = stream_get_contents($value);
        return is_string($data) ? $data : '';
    }

    return is_string($value) ? $value : '';
}

function client_ip(): string
{
    return (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
}

function check_rate_limit(PDO $db, string $action, int $limit, int $windowSeconds): bool
{
    global $MASTER_KEY;

    $bucket = substr(hash_hmac('sha256', $action . '|' . client_ip(), $MASTER_KEY), 0, 32);
    $now = time();

    try {
        $db->beginTransaction();

        $stmt = $db->prepare('SELECT window_start, hit_count FROM rate_limits WHERE bucket = :bucket');
        $stmt->execute([':bucket' => $bucket]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row || ($now - (int) $row['window_start']) >= $windowSeconds) {
            $stmt = $db->prepare(
                'INSERT OR REPLACE INTO rate_limits (bucket, window_start, hit_count)
                 VALUES (:bucket, :window_start, 1)'
            );
            $stmt->execute([
                ':bucket' => $bucket,
                ':window_start' => $now,
            ]);
            $db->commit();
            return true;
        }

        if ((int) $row['hit_count'] >= $limit) {
            $db->rollBack();
            return false;
        }

        $stmt = $db->prepare('UPDATE rate_limits SET hit_count = hit_count + 1 WHERE bucket = :bucket');
        $stmt->execute([':bucket' => $bucket]);
        $db->commit();

        return true;
    } catch (Throwable $e) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }

        // Fail open for availability. Rate limiting is defense-in-depth.
        return true;
    }
}

function purge_expired(PDO $db): void
{
    $now = time();

    try {
        $stmt = $db->prepare('DELETE FROM pastes WHERE expires_at IS NOT NULL AND expires_at <= :now');
        $stmt->execute([':now' => $now]);

        if (random_int(0, 99) === 0) {
            $stmt = $db->prepare('DELETE FROM rate_limits WHERE window_start < :cut');
            $stmt->execute([':cut' => $now - 86400]);
        }
    } catch (Throwable $e) {
        // Ignore cleanup failures.
    }
}

function fetch_paste(PDO $db, string $slug): ?array
{
    $stmt = $db->prepare(
        'SELECT slug, created_at, expires_at, has_password, kdf_salt, nonce, ciphertext, size_bytes
         FROM pastes
         WHERE slug = :slug'
    );
    $stmt->execute([':slug' => $slug]);

    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    return is_array($row) ? $row : null;
}

function delete_paste(PDO $db, string $slug): void
{
    $stmt = $db->prepare('DELETE FROM pastes WHERE slug = :slug');
    $stmt->execute([':slug' => $slug]);
}

function is_expired(array $paste): bool
{
    if ($paste['expires_at'] === null) {
        return false;
    }

    return (int) $paste['expires_at'] <= time();
}

function format_bytes(int $bytes): string
{
    if ($bytes >= 1048576) {
        return round($bytes / 1048576, 2) . ' MiB';
    }

    if ($bytes >= 1024) {
        return round($bytes / 1024, 2) . ' KiB';
    }

    return $bytes . ' B';
}

function format_utc(int $timestamp): string
{
    return gmdate('Y-m-d H:i:s', $timestamp) . ' UTC';
}

function format_expiry(?int $timestamp): string
{
    if ($timestamp === null) {
        return 'Never';
    }

    $remaining = $timestamp - time();

    if ($remaining <= 0) {
        return 'Expired';
    }

    if ($remaining < 60) {
        return 'less than 1 minute';
    }

    if ($remaining < 3600) {
        return (string) ceil($remaining / 60) . ' minutes';
    }

    if ($remaining < 86400) {
        return (string) ceil($remaining / 3600) . ' hours';
    }

    return (string) ceil($remaining / 86400) . ' days';
}

function render_page(string $title, string $body, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: text/html; charset=UTF-8');

    $css = <<<'CSS'
:root { color-scheme: light; }
body {
  margin: 0;
  font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
  background: #f5f6f8;
  color: #111827;
}
main {
  max-width: 900px;
  margin: 2rem auto;
  padding: 1.25rem;
  background: #fff;
  border: 1px solid #e5e7eb;
  border-radius: 10px;
  box-shadow: 0 1px 2px rgba(0,0,0,.04);
}
h1 {
  margin: 0 0 1rem;
  font-size: 1.35rem;
}
a { color: #1d4ed8; }
textarea, select, input[type="password"], button { font: inherit; }
textarea {
  width: 100%;
  box-sizing: border-box;
  min-height: 260px;
  padding: .6rem;
  border: 1px solid #cbd5e1;
  border-radius: 8px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}
label { display: block; margin: .8rem 0; }
select, input[type="password"] {
  padding: .45rem .55rem;
  border: 1px solid #cbd5e1;
  border-radius: 8px;
  background: #fff;
}
button {
  padding: .55rem .9rem;
  border: 0;
  border-radius: 8px;
  background: #111827;
  color: #fff;
  cursor: pointer;
}
button:hover { background: #1f2937; }
fieldset {
  border: 1px solid #e5e7eb;
  border-radius: 8px;
  padding: .8rem;
  margin: 1rem 0;
}
legend { font-weight: 600; padding: 0 .3rem; }
.error {
  padding: .75rem 1rem;
  border: 1px solid #dc2626;
  background: #fef2f2;
  color: #991b1b;
  border-radius: 8px;
}
.muted { color: #6b7280; font-size: .92rem; }
pre {
  margin: 1rem 0 0;
  padding: 1rem;
  background: #0f172a;
  color: #e2e8f0;
  border-radius: 8px;
  white-space: pre-wrap;
  word-break: break-word;
  overflow: auto;
}
dl.meta {
  display: grid;
  grid-template-columns: max-content 1fr;
  gap: .3rem .9rem;
  margin: 0 0 1rem;
}
dt { font-weight: 600; }
dd { margin: 0; }
code {
  background: #f1f5f9;
  padding: .1rem .3rem;
  border-radius: 4px;
}
CSS;

    echo '<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>' . e($title) . '</title>
<style>' . $css . '</style>
</head>
<body>
<main>
<h1>' . e($title) . '</h1>
' . $body . '
</main>
</body>
</html>';
}

function verify_csrf(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        return;
    }

    $token = $_POST['csrf'] ?? '';

    if (
        !is_string($token)
        || $token === ''
        || empty($_SESSION['csrf'])
        || !is_string($_SESSION['csrf'])
        || !hash_equals($_SESSION['csrf'], $token)
    ) {
        render_page(
            'Invalid request',
            '<p class="error">Invalid or expired form token. Please go back and try again.</p>'
            . '<p><a href="?">Home</a></p>',
            400
        );
        exit;
    }
}

function render_home(?string $error = null): void
{
    global $EXPIRE_OPTIONS;

    $body = '';

    if ($error !== null && $error !== '') {
        $body .= '<p class="error">' . e($error) . '</p>';
    }

    $options = '';
    foreach ($EXPIRE_OPTIONS as $key => $opt) {
        $selected = ($key === DEFAULT_EXPIRE_KEY) ? ' selected' : '';
        $options .= '<option value="' . e((string) $key) . '"' . $selected . '>'
            . e((string) $opt['label']) . '</option>';
    }

    $body .= '<form method="post" action="">' . csrf_field() . '
<label>Paste content<br>
<textarea name="content" rows="12" maxlength="' . MAX_CONTENT_BYTES . '" required placeholder="Paste text here..."></textarea>
</label>
<p class="muted">Maximum size: ' . e(format_bytes(MAX_CONTENT_BYTES)) . '. Content must be UTF-8 text.</p>

<label>Expiration
<select name="expires">' . $options . '</select>
</label>

<fieldset>
<legend>Password protection (optional)</legend>

<label>Password
<input type="password" name="password" autocomplete="new-password" minlength="' . MIN_PASSWORD_LENGTH . '">
</label>

<label>Confirm password
<input type="password" name="password_confirm" autocomplete="new-password" minlength="' . MIN_PASSWORD_LENGTH . '">
</label>

<p class="muted">
If set, the paste is encrypted with a key derived from this password.
Lost passwords cannot be recovered.
</p>
</fieldset>

<button type="submit">Create paste</button>
</form>';

    render_page('Secure Pastebin', $body);
}

function render_password_prompt(string $slug, ?string $error = null): void
{
    $body = '';

    if ($error !== null && $error !== '') {
        $body .= '<p class="error">' . e($error) . '</p>';
    }

    $action = '?s=' . rawurlencode($slug);

    $body .= '<form method="post" action="' . e($action) . '">' . csrf_field() . '
<label>Password
<input type="password" name="password" autocomplete="current-password" required>
</label>

<button type="submit">Unlock</button>
</form>

<p class="muted"><a href="?">Home</a></p>';

    render_page('Unlock paste', $body);
}

function render_paste(array $paste, string $plain, bool $unlockedWithPassword = false): void
{
    $createdAt = (int) $paste['created_at'];
    $expiresAt = $paste['expires_at'] === null ? null : (int) $paste['expires_at'];
    $size = (int) $paste['size_bytes'];

    $body = '<p><a href="?">Create another paste</a></p>';

    $body .= '<dl class="meta">';
    $body .= '<dt>Link</dt><dd><code>' . e($paste['slug']) . '</code></dd>';
    $body .= '<dt>Created</dt><dd>' . e(format_utc($createdAt)) . '</dd>';
    $body .= '<dt>Expires</dt><dd>' . e(format_expiry($expiresAt)) . '</dd>';
    $body .= '<dt>Size</dt><dd>' . e(format_bytes($size)) . '</dd>';
    $body .= '<dt>Password protected</dt><dd>'
        . (((int) $paste['has_password'] === 1) ? 'Yes' : 'No')
        . '</dd>';

    if ($unlockedWithPassword) {
        $body .= '<dt>Unlock</dt><dd>Password verified</dd>';
    }

    $body .= '</dl>';

    $body .= '<pre>' . e($plain) . '</pre>';

    render_page('Paste', $body);
}

function render_not_found(?string $message = null): void
{
    $message = $message ?? 'Paste not found.';

    render_page(
        'Not found',
        '<p class="error">' . e($message) . '</p><p><a href="?">Home</a></p>',
        404
    );
}

function render_error(string $message, int $status = 400): void
{
    render_page(
        'Error',
        '<p class="error">' . e($message) . '</p><p><a href="?">Home</a></p>',
        $status
    );
}

function handle_create(PDO $db): void
{
    global $EXPIRE_OPTIONS, $MASTER_KEY;

    $content = $_POST['content'] ?? '';

    if (!is_string($content) || $content === '') {
        render_home('Paste content is required.');
        return;
    }

    if (strpos($content, "\0") !== false) {
        render_home('Paste content cannot contain NUL bytes.');
        return;
    }

    $size = strlen($content);

    if ($size > MAX_CONTENT_BYTES) {
        render_home('Paste is too large. Maximum is ' . format_bytes(MAX_CONTENT_BYTES) . '.');
        return;
    }

    if (!mb_check_encoding($content, 'UTF-8')) {
        render_home('Paste content must be valid UTF-8.');
        return;
    }

    $expireKey = $_POST['expires'] ?? DEFAULT_EXPIRE_KEY;

    if (!is_string($expireKey) || !array_key_exists($expireKey, $EXPIRE_OPTIONS)) {
        render_home('Invalid expiration option.');
        return;
    }

    $expiresAt = $EXPIRE_OPTIONS[$expireKey]['seconds'] === null
        ? null
        : time() + (int) $EXPIRE_OPTIONS[$expireKey]['seconds'];

    $password = $_POST['password'] ?? '';
    $passwordConfirm = $_POST['password_confirm'] ?? '';

    if (!is_string($password) || !is_string($passwordConfirm)) {
        render_home('Invalid password input.');
        return;
    }

    $hasPassword = ($password !== '' || $passwordConfirm !== '');

    if ($hasPassword) {
        if (strlen($password) < MIN_PASSWORD_LENGTH) {
            render_home('Password must be at least ' . MIN_PASSWORD_LENGTH . ' characters.');
            return;
        }

        if ($password !== $passwordConfirm) {
            render_home('Passwords do not match.');
            return;
        }
    }

    if (!check_rate_limit($db, 'create', 20, 3600)) {
        render_home('Too many paste creations from this address. Please try again later.');
        return;
    }

    if ($hasPassword) {
        $salt = random_bytes(SALT_BYTES);
        $key = derive_password_key($password, $salt);
    } else {
        $salt = null;
        $key = $MASTER_KEY;
    }

    $encrypted = encrypt_message($content, $key);
    $nonce = $encrypted[0];
    $ciphertext = $encrypted[1];

    if ($hasPassword) {
        @sodium_memzero($key);
        @sodium_memzero($password);
        @sodium_memzero($passwordConfirm);
    }

    $sql = 'INSERT INTO pastes (
                slug,
                created_at,
                expires_at,
                has_password,
                kdf_salt,
                nonce,
                ciphertext,
                size_bytes
            ) VALUES (
                :slug,
                :created_at,
                :expires_at,
                :has_password,
                :kdf_salt,
                :nonce,
                :ciphertext,
                :size_bytes
            )';

    for ($attempt = 0; $attempt < 5; $attempt++) {
        $slug = generate_slug();

        try {
            $stmt = $db->prepare($sql);

            $stmt->bindValue(':slug', $slug, PDO::PARAM_STR);
            $stmt->bindValue(':created_at', time(), PDO::PARAM_INT);

            if ($expiresAt === null) {
                $stmt->bindValue(':expires_at', null, PDO::PARAM_NULL);
            } else {
                $stmt->bindValue(':expires_at', $expiresAt, PDO::PARAM_INT);
            }

            $stmt->bindValue(':has_password', $hasPassword ? 1 : 0, PDO::PARAM_INT);

            if ($salt === null) {
                $stmt->bindValue(':kdf_salt', null, PDO::PARAM_NULL);
            } else {
                $stmt->bindValue(':kdf_salt', $salt, PDO::PARAM_LOB);
            }

            $stmt->bindValue(':nonce', $nonce, PDO::PARAM_LOB);
            $stmt->bindValue(':ciphertext', $ciphertext, PDO::PARAM_LOB);
            $stmt->bindValue(':size_bytes', $size, PDO::PARAM_INT);

            $stmt->execute();

            header('Location: ?s=' . rawurlencode($slug), true, 303);
            exit;
        } catch (PDOException $e) {
            // SQLite constraint violation code is 19. Retry only on slug collision.
            if (((int) ($e->errorInfo[1] ?? 0)) !== 19) {
                error_log('pastebin insert error: ' . $e->getMessage());
                render_home('Database error. Please try again later.');
                return;
            }
        }
    }

    render_home('Could not generate a unique paste link. Please try again.');
}

function handle_view(PDO $db, string $slug): void
{
    global $MASTER_KEY;

    $paste = fetch_paste($db, $slug);

    if ($paste === null) {
        render_not_found();
        return;
    }

    if (is_expired($paste)) {
        delete_paste($db, $slug);
        render_not_found('This paste has expired.');
        return;
    }

    if ((int) $paste['has_password'] === 1) {
        render_password_prompt($slug);
        return;
    }

    $nonce = binary_value($paste['nonce']);
    $ciphertext = binary_value($paste['ciphertext']);

    $plain = decrypt_message($ciphertext, $nonce, $MASTER_KEY);

    if ($plain === false) {
        render_error('Unable to decrypt this paste. The server key may have changed.', 500);
        return;
    }

    render_paste($paste, $plain, false);
}

function handle_password_post(PDO $db, string $slug): void
{
    $paste = fetch_paste($db, $slug);

    if ($paste === null) {
        render_not_found();
        return;
    }

    if (is_expired($paste)) {
        delete_paste($db, $slug);
        render_not_found('This paste has expired.');
        return;
    }

    if ((int) $paste['has_password'] !== 1) {
        header('Location: ?s=' . rawurlencode($slug), true, 303);
        exit;
    }

    $password = $_POST['password'] ?? '';

    if (!is_string($password) || $password === '') {
        render_password_prompt($slug, 'Password is required.');
        return;
    }

    if (!check_rate_limit($db, 'auth:' . $slug, 10, 900)) {
        render_password_prompt($slug, 'Too many attempts. Please wait before trying again.');
        return;
    }

    $salt = binary_value($paste['kdf_salt']);

    if (strlen($salt) !== SALT_BYTES) {
        render_error('Paste metadata is invalid.', 500);
        return;
    }

    $key = derive_password_key($password, $salt);
    @sodium_memzero($password);

    $nonce = binary_value($paste['nonce']);
    $ciphertext = binary_value($paste['ciphertext']);

    $plain = decrypt_message($ciphertext, $nonce, $key);
    @sodium_memzero($key);

    if ($plain === false) {
        render_password_prompt($slug, 'Invalid password.');
        return;
    }

    render_paste($paste, $plain, true);
}

/*
 * CLI cleanup mode:
 *
 *   php /path/to/index.php
 *
 * Useful for cron:
 *
 *   * * * * * /usr/bin/php /var/www/pastebin/index.php >/dev/null 2>&1
 */
if (PHP_SAPI === 'cli') {
    try {
        $db = db();
        purge_expired($db);
        echo "Cleanup complete\n";
        exit(0);
    } catch (Throwable $e) {
        fwrite(STDERR, "Cleanup failed\n");
        exit(1);
    }
}

start_session();
send_security_headers();

try {
    $db = db();

    verify_csrf();

    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $slug = $_GET['s'] ?? '';

    if (!is_string($slug)) {
        $slug = '';
    }

    if ($method === 'POST') {
        if ($slug === '') {
            handle_create($db);
        } elseif (!is_valid_slug($slug)) {
            render_not_found();
        } else {
            handle_password_post($db, $slug);
        }
    } else {
        purge_expired($db);

        if ($slug === '') {
            render_home();
        } elseif (!is_valid_slug($slug)) {
            render_not_found();
        } else {
            handle_view($db, $slug);
        }
    }
} catch (Throwable $e) {
    error_log('pastebin error: ' . $e->getMessage());

    if (!headers_sent()) {
        render_error('Server error. Please try again later.', 500);
    } else {
        echo '<p>Server error.</p>';
    }
}