<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp;

use InvalidArgumentException;
use PDO;
use RuntimeException;

final class ApprovalGate
{
    private PDO $db;

    public function __construct(
        private readonly Config $config,
        private readonly CrmGateway $crm,
    ) {
        $file = $config->dataDir.'/approvals.sqlite3';
        $this->db = new PDO('sqlite:'.$file, options: [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
        @chmod($file, 0600);
        $this->db->exec('PRAGMA busy_timeout=3000');
        $this->db->exec('CREATE TABLE IF NOT EXISTS plans (
            id TEXT PRIMARY KEY,
            actor TEXT NOT NULL,
            payload TEXT NOT NULL,
            digest TEXT NOT NULL,
            state TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        )');
    }

    public static function canonical(array $plan): string
    {
        self::deepSort($plan);
        return (string) json_encode($plan, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    private static function deepSort(array &$value): void
    {
        if (array_is_list($value)) {
            foreach ($value as &$item) {
                if (is_array($item)) {
                    self::deepSort($item);
                }
            }
            return;
        }
        ksort($value, SORT_STRING);
        foreach ($value as &$item) {
            if (is_array($item)) {
                self::deepSort($item);
            }
        }
    }

    private function encrypt(string $raw): string
    {
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        return base64_encode($nonce.sodium_crypto_secretbox($raw, $nonce, $this->config->encryptionKey));
    }

    private function decrypt(string $encoded): string
    {
        $data = base64_decode($encoded, true);
        if (!is_string($data) || strlen($data) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + 16) {
            throw new RuntimeException('Corrupted encrypted proposal');
        }
        $raw = sodium_crypto_secretbox_open(
            substr($data, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            substr($data, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES),
            $this->config->encryptionKey
        );
        if (!is_string($raw)) {
            throw new RuntimeException('Cannot decrypt proposal');
        }
        return $raw;
    }

    public function prepare(
        string $actor,
        string $operation,
        string $module,
        ?string $recordId,
        array $changes,
        string $reason
    ): array {
        TokenVault::subject($actor);
        $changes = Policy::changes($module, $changes, $operation);
        if (strlen($reason) < 8 || strlen($reason) > 500) {
            throw new InvalidArgumentException('Reason must have 8 to 500 characters');
        }
        $before = [];
        $oldVersion = null;
        if ($operation === 'update' || $operation === 'delete') {
            $id = Policy::recordId($recordId ?? '');
            $selected = $operation === 'delete' ? ['name', 'date_modified'] : array_merge(array_keys($changes), ['date_modified']);
            $original = $this->crm->getRawForDiff($actor, $module, $id, $selected);
            $before = Policy::project($original['attributes'], $operation === 'delete' ? $selected : array_keys($changes));
            $oldVersion = $original['attributes']['date_modified'] ?? null;
            if (!is_string($oldVersion) || ($operation === 'delete' ? !isset($before['name']) : count($before) !== count($changes))) {
                throw new RuntimeException('Current values/version unavailable; cannot approve an update');
            }
            if ($operation === 'update' && $before === $changes) {
                throw new InvalidArgumentException('No differences to approve');
            }
            $recordId = $id;
        } else {
            if ($recordId !== null) {
                throw new InvalidArgumentException('Creation cannot specify record ID');
            }
        }
        $now = time();
        $plan = [
            'id' => self::uuid(),
            'actor_sub' => $actor,
            'operation' => $operation,
            'module' => $module,
            'record_id' => $recordId,
            'before' => $before,
            'after' => $changes,
            'date_modified_before' => $oldVersion,
            'reason' => $reason,
            'created_at' => $now,
            'expires_at' => $now + 900,
        ];
        $canonical = self::canonical($plan);
        $hash = hash('sha256', $canonical);
        $stmt = $this->db->prepare('INSERT INTO plans(id,actor,payload,digest,state,expires_at,created_at)
            VALUES(?,?,?,?,?,?,?)');
        $stmt->execute([$plan['id'], $actor, $this->encrypt($canonical),
                        $hash, 'pending', $plan['expires_at'], $now]);
        return [
            'browser_approval_url' => $this->config->oauthIssuer.'/approve?proposal_id='.$plan['id'],
            'proposal' => $plan,
            'digest' => $hash,
            'status' => 'pending',
            'approval_message' => self::approvalMessage($plan, $hash),
            'warning' => 'No SuiteCRM modification. Browser approval requires personal SuiteCRM authentication before execution.',
        ];
    }

    /** Prepare an individually versioned relationship modification. */
    public function prepareRelationship(
        string $actor,
        string $operation,
        string $module,
        string $recordId,
        string $linkField,
        string $relatedModule,
        string $relatedId,
        string $reason
    ): array {
        TokenVault::subject($actor);
        if (!in_array($operation, ['link', 'unlink'], true)) {
            throw new InvalidArgumentException('Unsupported relationship operation');
        }
        Policy::relationship($module, $linkField, $relatedModule);
        $recordId = Policy::recordId($recordId);
        $relatedId = Policy::recordId($relatedId);
        if (strlen($reason) < 8 || strlen($reason) > 500) {
            throw new InvalidArgumentException('Reason must have 8 to 500 characters');
        }
        // Require access to both records, even if the relation endpoint would
        // otherwise accept an opaque foreign ID.
        $original = $this->crm->getRawForDiff($actor, $module, $recordId, ['date_modified']);
        $this->crm->getRecord($actor, $relatedModule, $relatedId);
        $version = $original['attributes']['date_modified'] ?? null;
        if (!is_string($version)) {
            throw new RuntimeException('Source record version unavailable');
        }
        $now = time();
        $plan = [
            'id' => self::uuid(), 'actor_sub' => $actor, 'operation' => $operation,
            'module' => $module, 'record_id' => $recordId,
            'before' => ['date_modified' => $version],
            'after' => ['link_field' => $linkField, 'related_module' => $relatedModule,
                'related_id' => $relatedId],
            'date_modified_before' => $version,
            'reason' => $reason, 'created_at' => $now, 'expires_at' => $now + 900,
        ];
        $canonical = self::canonical($plan);
        $digest = hash('sha256', $canonical);
        $stmt = $this->db->prepare('INSERT INTO plans(id,actor,payload,digest,state,expires_at,created_at)
            VALUES(?,?,?,?,?,?,?)');
        $stmt->execute([$plan['id'], $actor, $this->encrypt($canonical),
            $digest, 'pending', $plan['expires_at'], $now]);
        return [
            'browser_approval_url' => $this->config->oauthIssuer.'/approve?proposal_id='.$plan['id'],
            'proposal' => $plan, 'digest' => $digest, 'status' => 'pending',
            'approval_message' => self::approvalMessage($plan, $digest),
            'warning' => 'No SuiteCRM relationship modified. Independent human approval required.',
        ];
    }

    public static function approvalMessage(array $plan, string $hash): string
    {
        return "SUITECRM_MCP_APPROVAL_V1\n".
            $plan['id']."\n".$plan['actor_sub']."\n".$hash."\n".
            $plan['expires_at']."\n";
    }

    private static function uuid(): string
    {
        $hex = bin2hex(random_bytes(16));
        return substr($hex, 0, 8).'-'.substr($hex, 8, 4).'-4'.
            substr($hex, 13, 3).'-a'.substr($hex, 17, 3).'-'.substr($hex, 20);
    }

    public function status(string $actor, string $proposalId): array
    {
        TokenVault::subject($actor);
        $id = Policy::recordId($proposalId);
        $stmt = $this->db->prepare('SELECT payload,digest,state,expires_at FROM plans WHERE id=? AND actor=?');
        $stmt->execute([$id, $actor]);
        $row = $stmt->fetch();
        if (!$row) {
            throw new RuntimeException('Proposal does not belong to this user');
        }
        $plan = json_decode($this->decrypt($row['payload']), true, 64, JSON_THROW_ON_ERROR);
        return [
            'browser_approval_url' => $this->config->oauthIssuer.'/approve?proposal_id='.$plan['id'],
            'proposal' => $plan,
            'digest' => $row['digest'],
            'status' => in_array($row['state'], ['pending', 'approved'], true) && time() >= (int)$row['expires_at']
                ? 'expired' : $row['state'],
            'approval_message' => self::approvalMessage($plan, $row['digest']),
        ];
    }

    /** Used only by the browser approval route after personal CRM OAuth login. */
    public function markBrowserApproved(string $actor, string $proposalId): void
    {
        if (!$this->config->allowWrites || !$this->config->workflowsReviewed) {
            throw new RuntimeException('Writes are disabled by server policy');
        }
        $view = $this->status($actor, $proposalId);
        if ($view['status'] !== 'pending') {
            throw new RuntimeException('Proposal is no longer pending');
        }
        $stmt = $this->db->prepare('UPDATE plans SET state=? WHERE id=? AND actor=? AND digest=? AND state=? AND expires_at>?');
        $stmt->execute(['approved', $proposalId, $actor, $view['digest'], 'pending', time()]);
        if ($stmt->rowCount() !== 1) {
            throw new RuntimeException('Proposal already approved or expired');
        }
    }

    /** Executes only after the browser-based independent human approval. */
    public function applyBrowserApproved(string $actor, string $proposalId): array
    {
        $view = $this->status($actor, $proposalId);
        if ($view['status'] !== 'approved') {
            throw new RuntimeException('Proposal requires a separate browser approval');
        }
        return $this->execute($actor, $proposalId, $view, 'approved');
    }

    public function apply(string $actor, string $proposalId, string $signature): array
    {
        if (!$this->config->allowWrites || !$this->config->workflowsReviewed) {
            throw new RuntimeException('Writes are disabled by server policy');
        }
        $pub = $this->config->approverPublicKey;
        if (!is_string($pub)) {
            throw new RuntimeException('No human approver public key configured');
        }
        $view = $this->status($actor, $proposalId);
        if ($view['status'] !== 'pending') {
            throw new RuntimeException('Proposal is no longer pending');
        }
        $plan = $view['proposal'];
        if (!in_array($plan['operation'] ?? null, ['create','update','delete','link','unlink'], true)) {
            throw new RuntimeException('Only individual record changes may be applied');
        }
        $proof = base64_decode($signature, true);
        if (!is_string($proof) || strlen($proof) !== SODIUM_CRYPTO_SIGN_BYTES
            || !sodium_crypto_sign_verify_detached($proof, $view['approval_message'], $pub)) {
            throw new RuntimeException('No valid independent human approval for this exact change');
        }
        return $this->execute($actor, $proposalId, $view);
    }

    /** All authorization paths share the same atomic claim and stale-state guard. */
    private function execute(string $actor, string $proposalId, array $view, string $expectedState = 'pending'): array
    {
        if (!$this->config->allowWrites || !$this->config->workflowsReviewed) {
            throw new RuntimeException('Writes are disabled by server policy');
        }
        if ($view['status'] !== $expectedState) {
            throw new RuntimeException('Proposal is no longer in an executable state');
        }
        $plan = $view['proposal'];
        // Atomic claim across workers prevents replay / duplicate execution.
        $this->db->beginTransaction();
        try {
            $stmt = $this->db->prepare('UPDATE plans SET state=? WHERE id=? AND actor=? AND state=? AND digest=? AND expires_at>?');
            $stmt->execute(['executing', $proposalId, $actor, $expectedState, $view['digest'], time()]);
            if ($stmt->rowCount() !== 1) {
                $this->db->rollBack();
                throw new RuntimeException('Proposal was already claimed or expired');
            }
            $this->db->commit();
        } catch (\Throwable $error) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            throw $error;
        }
        if (in_array($plan['operation'], ['update','delete','link','unlink'], true)) {
            try {
                $latest = $this->crm->getRawForDiff(
                    $actor,
                    $plan['module'],
                    $plan['record_id'],
                    in_array($plan['operation'], ['delete','link','unlink'], true)
                        ? array_keys($plan['before']) : array_merge(array_keys($plan['after']), ['date_modified'])
                );
                $attrs = $latest['attributes'];
                $prior = Policy::project($attrs, array_keys($plan['before']));
                if (self::canonical($prior) !== self::canonical($plan['before']) ||
                    ($attrs['date_modified'] ?? null) !== $plan['date_modified_before']) {
                    $this->finish($plan['id'], 'stale');
                    throw new RuntimeException('Record changed after human approval; prepare a new proposal');
                }
            } catch (\Throwable $error) {
                $this->finish($plan['id'], 'stale');
                throw new RuntimeException('Record revalidation failed; human review required');
            }
        }
        try {
            if (in_array($plan['operation'], ['link', 'unlink'], true)) {
                // The target still needs to exist and remain visible to this
                // user's personal SuiteCRM identity at execution time.
                $target = $plan['after'];
                Policy::relationship($plan['module'], $target['link_field'], $target['related_module']);
                $this->crm->getRecord($actor, $target['related_module'], $target['related_id']);
                $result = $this->crm->writeRelationship(
                    $actor,
                    $plan['operation'],
                    $plan['module'],
                    $plan['record_id'],
                    $target['link_field'],
                    $target['related_module'],
                    $target['related_id']
                );
            } else {
                $result = $this->crm->writeApproved(
                    $actor,
                    $plan['operation'],
                    $plan['module'],
                    $plan['after'],
                    $plan['record_id']
                );
            }
            $this->finish($plan['id'], 'applied');
            return ['status' => 'applied', 'proposal_id' => $plan['id'],
                    'record_id' => $result['record_id'], 'actor_sub' => $actor];
        } catch (\Throwable) {
            // Maybe the remote operation completed before transport failure;
            // never blindly retry an uncertain write.
            $this->finish($plan['id'], 'uncertain');
            throw new RuntimeException('Write outcome uncertain: manual CRM verification required; do not retry');
        }
    }

    private function finish(string $id, string $state): void
    {
        $stmt = $this->db->prepare('UPDATE plans SET state=? WHERE id=?');
        $stmt->execute([$state, $id]);
    }
}
