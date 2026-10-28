<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp;

use PDO;
use RuntimeException;

/** Independent human approval through an upstream SuiteCRM OAuth browser login. */
final class BrowserApproval
{
    private PDO $db;

    public function __construct(
        private readonly Config $config,
        private readonly ApprovalGate $gate,
        private readonly ApiClient $crm,
    ) {
        $this->db = new PDO('sqlite:'.$config->dataDir.'/browser-approval.sqlite3', options: [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        @chmod($config->dataDir.'/browser-approval.sqlite3', 0600);
        $this->db->exec('PRAGMA busy_timeout=3000');
        $this->db->exec('CREATE TABLE IF NOT EXISTS browser_logins (
            digest TEXT PRIMARY KEY, proposal_id TEXT NOT NULL, expires INTEGER NOT NULL
        )');
        $this->db->exec('CREATE TABLE IF NOT EXISTS browser_sessions (
            digest TEXT PRIMARY KEY, csrf_digest TEXT NOT NULL, proposal_id TEXT NOT NULL,
            subject TEXT NOT NULL, expires INTEGER NOT NULL
        )');
    }

    private static function nonce(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    private function requireEnabled(): void
    {
        if (!$this->config->allowWrites || !$this->config->workflowsReviewed) {
            throw new RuntimeException('Browser approvals are not enabled');
        }
    }

    public function begin(string $proposalId): string
    {
        $this->requireEnabled();
        $proposalId = Policy::recordId($proposalId);
        if (!$this->gate->isPending($proposalId)) {
            throw new RuntimeException('Proposal is not available for approval');
        }
        $this->db->prepare('DELETE FROM browser_logins WHERE expires<?')->execute([time()]);
        $this->db->prepare('DELETE FROM browser_sessions WHERE expires<?')->execute([time()]);
        // No proposal data is displayed until a matching personal CRM login.
        $state = self::nonce();
        $this->db->prepare('INSERT INTO browser_logins VALUES (?, ?, ?)')
            ->execute([hash('sha256', $state), $proposalId, time() + 300]);
        return $this->config->suiteCrmBaseUrl.'/Api/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $this->config->suiteCrmClientId,
            'redirect_uri' => $this->config->oauthIssuer.'/callback',
            'state' => $state,
        ], '', '&', PHP_QUERY_RFC3986);
    }

    public function hasState(string $state): bool
    {
        $q = $this->db->prepare('SELECT 1 FROM browser_logins WHERE digest=? AND expires>?');
        $q->execute([hash('sha256', $state), time()]);
        return $q->fetchColumn() !== false;
    }

    /** Consume the OAuth state, verify the CRM user, then issue a browser-only review session. */
    public function complete(string $state, string $code): array
    {
        $this->requireEnabled();
        $this->db->beginTransaction();
        try {
            $digest = hash('sha256', $state);
            $q = $this->db->prepare('SELECT proposal_id FROM browser_logins WHERE digest=? AND expires>?');
            $q->execute([$digest, time()]);
            $row = $q->fetch();
            if (!is_array($row)) {
                throw new RuntimeException('Invalid or expired browser login state');
            }
            $this->db->prepare('DELETE FROM browser_logins WHERE digest=?')->execute([$digest]);
            $this->db->commit();
        } catch (\Throwable $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            throw $e;
        }
        $tokens = $this->crm->request('POST', '/Api/access_token', payload: [
            'grant_type' => 'authorization_code',
            'client_id' => $this->config->suiteCrmClientId,
            'client_secret' => $this->config->suiteCrmClientSecret,
            'code' => $code,
            'redirect_uri' => $this->config->oauthIssuer.'/callback',
        ]);
        $access = $tokens['access_token'] ?? null;
        if (!is_string($access) || $access === '') {
            throw new RuntimeException('Upstream CRM authorization failed');
        }
        $subject = $this->crm->currentUserId($access);
        $proposal = $this->gate->status($subject, $row['proposal_id']);
        if ($proposal['status'] !== 'pending') {
            throw new RuntimeException('Proposal is no longer pending');
        }
        $ticket = self::nonce();
        $csrf = self::nonce();
        $this->db->prepare('INSERT INTO browser_sessions VALUES (?, ?, ?, ?, ?)')
            ->execute([hash('sha256', $ticket), hash('sha256', $csrf),
                $row['proposal_id'], $subject, time() + 300]);
        return ['ticket' => $ticket, 'csrf' => $csrf, 'proposal' => $proposal];
    }

    public function approve(string $ticket, string $csrf): string
    {
        $this->requireEnabled();
        $this->db->beginTransaction();
        try {
            $digest = hash('sha256', $ticket);
            $q = $this->db->prepare('SELECT * FROM browser_sessions WHERE digest=? AND expires>?');
            $q->execute([$digest, time()]);
            $row = $q->fetch();
            if (!is_array($row) || !hash_equals($row['csrf_digest'], hash('sha256', $csrf))) {
                throw new RuntimeException('Invalid or expired browser approval session');
            }
            $this->db->prepare('DELETE FROM browser_sessions WHERE digest=?')->execute([$digest]);
            $this->db->commit();
        } catch (\Throwable $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            throw $e;
        }
        $this->gate->markBrowserApproved($row['subject'], $row['proposal_id']);
        return $row['proposal_id'];
    }
}
