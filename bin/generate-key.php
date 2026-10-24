<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);
/** Generate the independent token-encryption key for the MCP host only.
 * Usage: php bin/generate-key.php /run/keys/token_encryption_key
 */
$argv = $_SERVER['argv'] ?? [];
$argc = count($argv);

if (PHP_SAPI !== 'cli' || $argc !== 2) {
    exit(2);
}
$path = $argv[1];
if (file_exists($path) || is_link($path)) {
    fwrite(STDERR, "Refusing to overwrite token encryption secret\n");
    exit(3);
}
$fp = @fopen($path, 'x');
if ($fp === false) {
    fwrite(STDERR, "Cannot create key file\n");
    exit(4);
}
fwrite($fp, base64_encode(random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES))."\n");
fclose($fp);
chmod($path, 0600);
echo "Secret generated (value not printed).\n";
