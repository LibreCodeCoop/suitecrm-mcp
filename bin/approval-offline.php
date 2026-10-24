<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

/** This tool MUST be run on the manager's SEPARATE trusted computer, not MCP host.
 *  Requires PHP with ext-sodium. No SuiteCRM or MCP credentials are needed.
 *
 * Keypair: php approval-offline.php generate /safe/private.key /safe/public.key
 * Sign:    php approval-offline.php sign /safe/private.key proposal.json
 */
$argv = $_SERVER['argv'] ?? [];
$argc = count($argv);

if (PHP_SAPI !== 'cli') {
    exit(1);
}
if ($argc < 2) {
    fwrite(STDERR, "Use generate PRIVATE_PATH PUBLIC_PATH, or sign PRIVATE_PATH PROPOSAL_PATH\n");
    exit(2);
}
if (is_file(dirname(__DIR__).'/.env') ||
    is_file(dirname(__DIR__).'/.env.deploy')) {
    fwrite(STDERR, "Refusing to sign/generate keys on the MCP host. Copy only this script to your trusted computer.\n");
    exit(3);
}
$operation = $argv[1];
if ($operation === 'generate' && $argc === 4) {
    $keypair = sodium_crypto_sign_keypair();
    $private = sodium_crypto_sign_secretkey($keypair);
    $public = sodium_crypto_sign_publickey($keypair);
    foreach ([$argv[2], $argv[3]] as $path) {
        if (file_exists($path) || is_link($path)) {
            fwrite(STDERR, "File already exists; refusing overwrite\n");
            exit(3);
        }
    }
    // On trusted offline device; encrypt the private key with a passphrase.
    fwrite(STDERR, 'Passphrase (minimum 16 characters): ');
    shell_exec('stty -echo');
    $pass = rtrim((string) fgets(STDIN), "\r\n");
    shell_exec('stty echo');
    fwrite(STDERR, "\n");
    if (strlen($pass) < 16) {
        fwrite(STDERR, "Passphrase too short\n");
        exit(3);
    }
    $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
    $derived = sodium_crypto_pwhash(
        SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
        $pass,
        $salt,
        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
    );
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $cipher = sodium_crypto_secretbox($private, $nonce, $derived);
    $data = base64_encode($salt.$nonce.$cipher);
    file_put_contents($argv[2], $data, LOCK_EX);
    chmod($argv[2], 0600);
    file_put_contents($argv[3], base64_encode($public), LOCK_EX);
    chmod($argv[3], 0644);
    echo "Copy ONLY the PUBLIC KEY file to the MCP server secrets/approver_public_key.\n";
    exit(0);
}
if ($operation === 'sign' && $argc === 4) {
    if (!function_exists('posix_isatty') || !posix_isatty(STDIN)) {
        throw new RuntimeException('Human interactive approval is mandatory');
    }
    $review = json_decode((string)file_get_contents($argv[3]), true, 64, JSON_THROW_ON_ERROR);
    $plan = $review['proposal'] ?? null;
    if (!is_array($plan) || !isset($plan['id'], $plan['actor_sub'], $plan['expires_at'], $review['digest'])) {
        throw new RuntimeException('Malformed proposed change');
    }
    if ($plan['expires_at'] <= time()) {
        throw new RuntimeException('Proposal expired');
    }
    $canonical = function (array $value): string {
        $sort = function (array &$v) use (&$sort): void {
            if (!array_is_list($v)) {
                ksort($v, SORT_STRING);
            }
            foreach ($v as &$x) {
                if (is_array($x)) {
                    $sort($x);
                }
            }
        };
        $sort($value);
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    };
    $digest = hash('sha256', $canonical($plan));
    if (!hash_equals($digest, $review['digest'])) {
        throw new RuntimeException('Proposal hash mismatch');
    }
    $message = "SUITECRM_MCP_APPROVAL_V1\n".
        $plan['id']."\n".$plan['actor_sub']."\n".$digest."\n".$plan['expires_at']."\n";
    echo json_encode($plan, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)."\n";
    fwrite(STDERR, "REVIEW ALL FIELDS AND EFFECTS OF THIS SINGLE OPERATION.\n");
    $suffix = substr($plan['id'], -8);
    fwrite(STDERR, "Type 'APPROVE ".$suffix."' to approve exactly this proposal: ");
    if (trim((string)fgets(STDIN)) !== 'APPROVE '.$suffix) {
        fwrite(STDERR, "Rejected.\n");
        exit(4);
    }
    fwrite(STDERR, 'Private key passphrase: ');
    shell_exec('stty -echo');
    $pass = rtrim((string)fgets(STDIN), "\r\n");
    shell_exec('stty echo');
    fwrite(STDERR, "\n");
    $cipher = base64_decode(trim((string)file_get_contents($argv[2])), true);
    $salt = substr($cipher, 0, SODIUM_CRYPTO_PWHASH_SALTBYTES);
    $nonce = substr($cipher, SODIUM_CRYPTO_PWHASH_SALTBYTES, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $derived = sodium_crypto_pwhash(
        SODIUM_CRYPTO_SECRETBOX_KEYBYTES,
        $pass,
        $salt,
        SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
        SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE
    );
    $private = sodium_crypto_secretbox_open(
        substr($cipher, SODIUM_CRYPTO_PWHASH_SALTBYTES + SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
        $nonce,
        $derived
    );
    if (!is_string($private)) {
        throw new RuntimeException('Private key decryption failed');
    }
    echo base64_encode(sodium_crypto_sign_detached($message, $private))."\n";
    echo "Paste only this signature into the manager-approved execution step.\n";
    exit(0);
}
fwrite(STDERR, "Invalid command\n");
exit(2);
