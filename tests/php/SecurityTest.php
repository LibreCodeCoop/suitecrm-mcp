<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp\Tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SuiteCrmMcp\ApprovalGate;
use SuiteCrmMcp\Config;
use SuiteCrmMcp\CrmGateway;
use SuiteCrmMcp\Policy;
use SuiteCrmMcp\TokenVault;

final class FakeCrm implements CrmGateway
{
    public array $calls = [];
    public string $modified = '2026-10-22T10:00:00+00:00';
    public string $nextStep = 'First contact';
    public function linked(string $subject): bool
    {
        return true;
    }
    public function modules(string $subject): array
    {
        return ['Opportunities'];
    }
    public function schema(string $subject, string $module): array
    {
        return [];
    }
    public function listRecords(string $subject, string $module, array $fields = [], int $page = 1, int $pageSize = 10): array
    {
        return [];
    }
    public function getRecord(string $subject, string $module, string $recordId, array $fields = []): array
    {
        return ['id' => $recordId, 'attributes' => [
            'next_step' => $this->nextStep,
            'date_modified' => $this->modified,
        ]];
    }
    public function getRawForDiff(string $subject, string $module, string $id, array $fields): array
    {
        return $this->getRecord($subject, $module, $id, $fields);
    }
    public function writeApproved(string $subject, string $method, string $module, array $attrs, ?string $id): array
    {
        $this->calls[] = compact('subject', 'method', 'module', 'attrs', 'id');
        $this->nextStep = $attrs['next_step'] ?? $this->nextStep;
        $this->modified = '2026-10-22T10:30:00+00:00';
        return ['record_id' => $id];
    }
}

final class SecurityTest extends TestCase
{
    private string $temp;
    private Config $config;
    private FakeCrm $crm;
    private string $managerSecret;
    private string $managerPublic;

    protected function setUp(): void
    {
        $this->temp = sys_get_temp_dir().'/librecode-mcp-test-'.bin2hex(random_bytes(6));
        mkdir($this->temp, 0700, true);
        $pair = sodium_crypto_sign_keypair();
        $this->managerSecret = sodium_crypto_sign_secretkey($pair);
        $this->managerPublic = sodium_crypto_sign_publickey($pair);
        $this->config = new Config(
            suiteCrmBaseUrl: 'https://crm.example.com/legacy',
            suiteCrmClientId: 'test-only',
            suiteCrmClientSecret: 'test-only',
            oauthIssuer: 'https://crm.example.com/suitecrm-mcp-auth',
            mcpResourceUri: 'https://mcp.example.test/mcp',
            dataDir: $this->temp,
            encryptionKey: random_bytes(32),
            approverPublicKey: $this->managerPublic,
            allowWrites: false,
            workflowsReviewed: false,
            allowedHosts: ['nginx'],
        );
        $this->crm = new FakeCrm();
    }

    protected function tearDown(): void
    {
        foreach (glob($this->temp.'/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->temp);
    }

    public function testPolicyDeniesSensitiveAndUnstructuredChanges(): void
    {
        foreach (['bank_c','cpf_c','pix_key_c','password','oauth_tokens'] as $field) {
            try {
                Policy::fields('Accounts', [$field]);
                self::fail('Allowed '.$field);
            } catch (\InvalidArgumentException $ok) {
                self::assertTrue(true);
            }
        }
        $this->expectException(\InvalidArgumentException::class);
        Policy::changes('Notes', ['description' => 'Overwrite the past'], 'update');
    }

    public function testEncryptedPerUserCredentialsAreIsolated(): void
    {
        $vault = new TokenVault($this->config);
        $crmId = '11111111-2222-4333-a444-555555555555';
        $vault->save('member-01', $crmId, 'access-secret', 'refresh-secret', time() + 500);
        self::assertTrue($vault->linked('member-01'));
        self::assertFalse($vault->linked('member-02'));
        $tokens = $vault->load('member-01');
        self::assertSame('refresh-secret', $tokens['refresh_token']);
        $raw = file_get_contents($this->temp.'/user-tokens.sqlite3');
        self::assertStringNotContainsString('refresh-secret', $raw);
        self::assertStringNotContainsString('access-secret', $raw);
        self::assertSame(0600, fileperms($this->temp.'/user-tokens.sqlite3') & 0777);
        $this->expectException(RuntimeException::class);
        $vault->load('member-02');
    }

    private function prepare(ApprovalGate $gate): array
    {
        return $gate->prepare(
            'member-01',
            'update',
            'Opportunities',
            '11111111-2222-4333-a444-555555555555',
            ['next_step' => 'Call tomorrow'],
            'Operator requested a reminder to call',
        );
    }

    public function testProposalIsNotCommercialWrite(): void
    {
        $gate = new ApprovalGate($this->config, $this->crm);
        $plan = $this->prepare($gate);
        self::assertSame([], $this->crm->calls);
        self::assertSame('First contact', $plan['proposal']['before']['next_step']);
        self::assertSame('Call tomorrow', $plan['proposal']['after']['next_step']);
        self::assertSame('pending', $gate->status('member-01', $plan['proposal']['id'])['status']);
        $this->expectException(RuntimeException::class);
        $gate->status('member-02', $plan['proposal']['id']);
    }

    public function testEvenValidHumanSignatureCannotBypassDisabledGate(): void
    {
        $gate = new ApprovalGate($this->config, $this->crm);
        $proposal = $this->prepare($gate);
        $signature = base64_encode(sodium_crypto_sign_detached(
            $proposal['approval_message'],
            $this->managerSecret
        ));
        try {
            $gate->apply('member-01', $proposal['proposal']['id'], $signature);
            self::fail('Write gate bypassed');
        } catch (RuntimeException $ok) {
            self::assertSame([], $this->crm->calls);
        }
    }

    public function testInteractiveConfirmationIsExactActorBoundAndOneTime(): void
    {
        $gate = new ApprovalGate($this->enabledConfig(), $this->crm);
        $proposal = $this->prepare($gate);
        $id = $proposal['proposal']['id'];
        $confirmation = 'CONFIRM '.$id.' '.$proposal['digest'];
        try {
            $gate->applyConfirmed('member-01', $id, 'CONFIRM '.$id.' invalid');
            self::fail('Wrong confirmation accepted');
        } catch (RuntimeException $expected) {
            self::assertSame([], $this->crm->calls);
        }
        try {
            $gate->applyConfirmed('member-02', $id, $confirmation);
            self::fail('Cross-user approval accepted');
        } catch (RuntimeException $expected) {
            self::assertSame([], $this->crm->calls);
        }
        self::assertSame('applied', $gate->applyConfirmed('member-01', $id, $confirmation)['status']);
        self::assertCount(1, $this->crm->calls);
        $this->expectException(RuntimeException::class);
        try {
            $gate->applyConfirmed('member-01', $id, $confirmation);
        } finally {
            self::assertCount(1, $this->crm->calls);
        }
    }

    public function testInteractiveConfirmationRespectsDisabledWriteGates(): void
    {
        $gate = new ApprovalGate($this->config, $this->crm);
        $proposal = $this->prepare($gate);
        $this->expectException(RuntimeException::class);
        try {
            $gate->applyConfirmed(
                'member-01',
                $proposal['proposal']['id'],
                'CONFIRM '.$proposal['proposal']['id'].' '.$proposal['digest']
            );
        } finally {
            self::assertSame([], $this->crm->calls);
        }
    }

    public function testWrongSignatureCannotTriggerWrite(): void
    {
        $gate = new ApprovalGate($this->enabledConfig(), $this->crm);
        $proposal = $this->prepare($gate);
        $attacker = sodium_crypto_sign_keypair();
        $wrong = base64_encode(sodium_crypto_sign_detached(
            $proposal['approval_message'],
            sodium_crypto_sign_secretkey($attacker)
        ));
        $this->expectException(RuntimeException::class);
        try {
            $gate->apply('member-01', $proposal['proposal']['id'], $wrong);
        } finally {
            self::assertSame([], $this->crm->calls);
        }
    }

    public function testHumanApprovalCanApplyExactlyOnceToMatchingUser(): void
    {
        $gate = new ApprovalGate($this->enabledConfig(), $this->crm);
        $proposal = $this->prepare($gate);
        $signature = base64_encode(sodium_crypto_sign_detached(
            $proposal['approval_message'],
            $this->managerSecret
        ));
        self::assertSame([], $this->crm->calls);
        try {
            $gate->apply('member-02', $proposal['proposal']['id'], $signature);
            self::fail('Cross-user privilege escalation');
        } catch (RuntimeException $expected) {
            self::assertSame([], $this->crm->calls);
        }
        $result = $gate->apply('member-01', $proposal['proposal']['id'], $signature);
        self::assertSame('applied', $result['status']);
        self::assertCount(1, $this->crm->calls);
        try {
            $gate->apply('member-01', $proposal['proposal']['id'], $signature);
            self::fail('Replayed signature');
        } catch (RuntimeException $expected) {
            self::assertCount(1, $this->crm->calls);
        }
    }

    public function testChangedRecordInvalidatesManagerSignature(): void
    {
        $gate = new ApprovalGate($this->enabledConfig(), $this->crm);
        $proposal = $this->prepare($gate);
        $sig = base64_encode(sodium_crypto_sign_detached(
            $proposal['approval_message'],
            $this->managerSecret
        ));
        $this->crm->modified = '2026-10-22T12:00:00+00:00';
        try {
            $gate->apply('member-01', $proposal['proposal']['id'], $sig);
            self::fail('Stale change accepted');
        } catch (RuntimeException $expected) {
            self::assertSame([], $this->crm->calls);
        }
    }

    private function enabledConfig(): Config
    {
        return new Config(
            suiteCrmBaseUrl: $this->config->suiteCrmBaseUrl,
            suiteCrmClientId: 'test',
            suiteCrmClientSecret: 'test',
            oauthIssuer: $this->config->oauthIssuer,
            mcpResourceUri: $this->config->mcpResourceUri,
            dataDir: $this->config->dataDir,
            encryptionKey: $this->config->encryptionKey,
            approverPublicKey: $this->managerPublic,
            allowWrites: true,
            workflowsReviewed: true,
            allowedHosts: ['nginx'],
        );
    }
}
