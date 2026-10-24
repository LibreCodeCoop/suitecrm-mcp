<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp;

use PDO;
use RuntimeException;

final class TokenVault
{
    private PDO $db;

    public function __construct(private readonly Config $config)
    {
        if (!is_dir($config->dataDir) && !mkdir($config->dataDir, 0700, true) && !is_dir($config->dataDir)) {
            throw new RuntimeException('Cannot create the data directory');
        }
        $file = $config->dataDir.'/user-tokens.sqlite3';
        $this->db = new PDO('sqlite:'.$file, options: [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        @chmod($file, 0600);
        $this->db->exec('PRAGMA busy_timeout=3000');
        $this->db->exec('CREATE TABLE IF NOT EXISTS links (
            subject TEXT PRIMARY KEY,
            crm_user_id TEXT NOT NULL,
            encrypted_credentials TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        )');
        // Monotonic generation blocks old JWTs, including after a new login.
        // Blocked subjects cannot relink until explicitly re-enabled by an admin.
        $this->db->exec('CREATE TABLE IF NOT EXISTS access_state (
            subject TEXT PRIMARY KEY,
            generation INTEGER NOT NULL,
            blocked INTEGER NOT NULL DEFAULT 0
        )');
    }

    public function save(string $subject, string $crmUserId, string $accessToken, string $refreshToken, int $expiry): void
    {
        $this->withSubjectLock($subject, function () use (
            $subject,
            $crmUserId,
            $accessToken,
            $refreshToken,
            $expiry
        ): void {
            $this->saveUnlocked($subject, $crmUserId, $accessToken, $refreshToken, $expiry);
        });
    }

    private function saveUnlocked(string $subject, string $crmUserId, string $accessToken, string $refreshToken, int $expiry): void
    {
        self::subject($subject);
        Policy::recordId($crmUserId);
        if ($this->isBlocked($subject)) {
            throw new RuntimeException('MCP identity disabled by administrator');
        }
        $data = json_encode(['access_token' => $accessToken, 'refresh_token' => $refreshToken,
                'expires_at' => $expiry], JSON_THROW_ON_ERROR);
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $encrypted = base64_encode($nonce.sodium_crypto_secretbox($data, $nonce, $this->config->encryptionKey));
        $q = $this->db->prepare('INSERT INTO links (subject,crm_user_id,encrypted_credentials,updated_at)
            VALUES (?,?,?,?) ON CONFLICT(subject) DO UPDATE SET
            crm_user_id=excluded.crm_user_id, encrypted_credentials=excluded.encrypted_credentials,
            updated_at=excluded.updated_at');
        $q->execute([$subject, strtolower($crmUserId), $encrypted, time()]);
    }

    /** Serialize the upstream refresh grant, which may invalidate previous refresh tokens. */
    public function currentCredentials(string $subject, ApiClient $http): array
    {
        return $this->withSubjectLock($subject, function () use ($subject, $http): array {
            $tokens = $this->load($subject);
            if ($tokens['expires_at'] < time() + 60) {
                $updated = $http->refresh($tokens['refresh_token']);
                if (!is_string($updated['access_token'] ?? null)
                    || !is_string($updated['refresh_token'] ?? null)) {
                    throw new RuntimeException('SuiteCRM personal token refresh failed; relink required');
                }
                $this->saveUnlocked(
                    $subject,
                    $tokens['crm_user_id'],
                    $updated['access_token'],
                    $updated['refresh_token'],
                    time() + max(60, (int) ($updated['expires_in'] ?? 600))
                );
                $tokens = $this->load($subject);
            }
            return $tokens;
        });
    }

    public function load(string $subject): array
    {
        self::subject($subject);
        $q = $this->db->prepare('SELECT crm_user_id,encrypted_credentials FROM links WHERE subject = ?');
        $q->execute([$subject]);
        $row = $q->fetch();
        if (!is_array($row)) {
            throw new RuntimeException('SuiteCRM account not linked for this identity');
        }
        $cipher = base64_decode($row['encrypted_credentials'], true);
        if (!is_string($cipher) || strlen($cipher) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + 16) {
            throw new RuntimeException('Damaged encrypted account credential');
        }
        $nonce = substr($cipher, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $plain = sodium_crypto_secretbox_open(
            substr($cipher, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            $nonce,
            $this->config->encryptionKey
        );
        if ($plain === false) {
            throw new RuntimeException('Encrypted account credential cannot be opened');
        }
        $tokens = json_decode($plain, true, 32, JSON_THROW_ON_ERROR);
        if (!is_array($tokens) || !is_string($tokens['access_token'] ?? null)
            || !is_string($tokens['refresh_token'] ?? null) || !is_int($tokens['expires_at'] ?? null)) {
            throw new RuntimeException('Invalid account credential format');
        }
        return ['crm_user_id' => $row['crm_user_id']] + $tokens;
    }

    public function linked(string $subject): bool
    {
        self::subject($subject);
        $q = $this->db->prepare('SELECT 1 FROM links WHERE subject = ?');
        $q->execute([$subject]);
        return (bool) $q->fetchColumn();
    }

    /** The version included in an issued access token; revoked versions never return. */
    public function generation(string $subject): int
    {
        self::subject($subject);
        $q = $this->db->prepare('SELECT generation FROM access_state WHERE subject = ?');
        $q->execute([$subject]);
        $generation = $q->fetchColumn();
        return $generation === false ? 0 : (int) $generation;
    }

    public function isBlocked(string $subject): bool
    {
        self::subject($subject);
        $q = $this->db->prepare('SELECT blocked FROM access_state WHERE subject = ?');
        $q->execute([$subject]);
        return (int) $q->fetchColumn() === 1;
    }

    public function activeAtGeneration(string $subject, int $generation): bool
    {
        return $generation >= 0 && !$this->isBlocked($subject)
            && $this->linked($subject) && $this->generation($subject) === $generation;
    }

    /** A small, per-user critical section; never hold it across unrelated users. */
    public function withSubjectLock(string $subject, callable $callback): mixed
    {
        self::subject($subject);
        $filename = $this->config->dataDir.'/lock-'.hash('sha256', $subject).'.lck';
        $handle = fopen($filename, 'c');
        if ($handle === false) {
            throw new RuntimeException('Cannot establish personal token lock');
        }
        @chmod($filename, 0600);
        try {
            if (!flock($handle, LOCK_EX)) {
                throw new RuntimeException('Cannot acquire personal token lock');
            }
            return $callback();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /** Invalidate all issued JWT generations and prevent any future relink. */
    public function revoke(string $subject): void
    {
        $this->withSubjectLock($subject, function () use ($subject): void {
            $this->db->beginTransaction();
            try {
                $this->db->prepare('INSERT INTO access_state (subject,generation,blocked)
                    VALUES (?,1,1) ON CONFLICT(subject) DO UPDATE SET
                    generation=generation+1, blocked=1')->execute([$subject]);
                $this->db->prepare('DELETE FROM links WHERE subject = ?')->execute([$subject]);
                $this->db->commit();
            } catch (\Throwable $e) {
                $this->db->rollBack();
                throw $e;
            }
        });
    }

    /** Admin-only. A new interactive SuiteCRM login is still required. */
    public function unblock(string $subject): void
    {
        $this->withSubjectLock($subject, function () use ($subject): void {
            $this->db->prepare('UPDATE access_state SET blocked=0 WHERE subject=?')
                ->execute([$subject]);
        });
    }

    public static function subject(string $subject): string
    {
        if ($subject === '' || strlen($subject) > 255 || preg_match('/[^A-Za-z0-9._:@-]/', $subject)) {
            throw new RuntimeException('Invalid authenticated SuiteCRM subject');
        }
        return $subject;
    }
}
