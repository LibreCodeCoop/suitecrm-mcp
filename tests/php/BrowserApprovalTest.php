<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp\Tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SuiteCrmMcp\ApiClient;
use SuiteCrmMcp\ApprovalGate;
use SuiteCrmMcp\BrowserApproval;
use SuiteCrmMcp\Config;
use SuiteCrmMcp\CrmGateway;

final class BrowserCrmClient implements ApiClient
{
    public string $subject = 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa';

    public function request(string $method, string $path, ?string $bearer = null, ?array $payload = null, array $query = []): array
    {
        if ($method !== 'POST' || $path !== '/Api/access_token' || ($payload['grant_type'] ?? null) !== 'authorization_code') {
            throw new RuntimeException('Unexpected OAuth request');
        }
        return ['access_token' => 'synthetic-browser-access'];
    }

    public function refresh(string $refreshToken): array
    {
        throw new RuntimeException('Unexpected refresh');
    }

    public function currentUserId(string $token): string
    {
        if ($token !== 'synthetic-browser-access') {
            throw new RuntimeException('Unexpected bearer');
        }
        return $this->subject;
    }
}

final class BrowserApprovalTest extends TestCase
{
    private string $dir;
    private Config $config;
    private CrmGateway $gateway;
    private BrowserCrmClient $oauth;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/mcp-approval-test-'.bin2hex(random_bytes(8));
        mkdir($this->dir, 0700, true);
        $this->config = new Config(
            'https://crm.example.com/legacy',
            'synthetic-client',
            'synthetic-secret',
            'https://crm.example.com/suitecrm-mcp-auth',
            'https://mcp.example.test',
            $this->dir,
            random_bytes(32),
            null,
            true,
            true,
            ['nginx']
        );
        $this->gateway = $this->createStub(CrmGateway::class);
        $this->gateway->method('writeApproved')->willReturn(['record_id' => '11111111-2222-4333-a444-555555555555']);
        $this->oauth = new BrowserCrmClient();
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir.'/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->dir);
    }

    private function setupReview(): array
    {
        $gate = new ApprovalGate($this->config, $this->gateway);
        $browser = new BrowserApproval($this->config, $gate, $this->oauth);
        $plan = $gate->prepare(
            $this->oauth->subject,
            'create',
            'Accounts',
            null,
            ['name' => 'SYNTHETIC BROWSER APPROVAL TEST'],
            'Synthetic browser test only'
        );
        $url = $browser->begin($plan['proposal']['id']);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        return [$gate, $browser, $plan['proposal']['id'], $query['state']];
    }

    public function testBrowserOAuthBindsRealUserToReviewAndRequiresCsrf(): void
    {
        [$gate, $browser, $id, $state] = $this->setupReview();
        self::assertTrue($browser->hasState($state));
        $review = $browser->complete($state, 'synthetic-code');
        self::assertFalse($browser->hasState($state));
        self::assertSame($id, $review['proposal']['proposal']['id']);
        try {
            $browser->approve($review['ticket'], 'invalid-csrf');
            self::fail('Browser CSRF check bypassed');
        } catch (RuntimeException) {
            self::assertSame('pending', $gate->status($this->oauth->subject, $id)['status']);
        }
        self::assertSame($id, $browser->approve($review['ticket'], $review['csrf']));
        self::assertSame('approved', $gate->status($this->oauth->subject, $id)['status']);
        self::assertSame('applied', $gate->applyBrowserApproved($this->oauth->subject, $id)['status']);
        $this->expectException(RuntimeException::class);
        $browser->approve($review['ticket'], $review['csrf']);
    }

    public function testWrongCrmIdentityCannotApproveSomeoneElsesProposal(): void
    {
        [$gate, $browser, $id, $state] = $this->setupReview();
        $this->oauth->subject = 'bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb';
        $this->expectException(RuntimeException::class);
        try {
            $browser->complete($state, 'synthetic-code');
        } finally {
            self::assertSame('pending', $gate->status('aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa', $id)['status']);
        }
    }

    public function testCallbackStateIsOneTimeEvenWhenAuthenticationFails(): void
    {
        [, $browser, , $state] = $this->setupReview();
        $browser->complete($state, 'synthetic-code');
        $this->expectException(RuntimeException::class);
        $browser->complete($state, 'synthetic-code');
    }
}
