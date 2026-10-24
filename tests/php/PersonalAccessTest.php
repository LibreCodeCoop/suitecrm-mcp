<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp\Tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SuiteCrmMcp\ApiClient;
use SuiteCrmMcp\Config;
use SuiteCrmMcp\SuiteCrmRepository;
use SuiteCrmMcp\TokenVault;

final class RecordingPersonalApi implements ApiClient
{
    public array $bearers = [];
    public int $refreshCalls = 0;
    public string $aliceId = 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa';
    public string $bobId = 'bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb';

    public function currentUserId(string $token): string
    {
        return match ($token) {
            'bearer-alice', 'bearer-alice-new' => $this->aliceId,
            'bearer-bob' => $this->bobId,
            default => throw new RuntimeException('Unrecognized test bearer'),
        };
    }

    public function request(
        string $method,
        string $path,
        ?string $bearer = null,
        ?array $payload = null,
        array $query = []
    ): array {
        if ($method !== 'GET') {
            throw new RuntimeException('Tests never allow CRM write');
        }
        $this->bearers[] = $bearer;
        if ($path === '/Api/V8/module/Accounts') {
            $name = match ($bearer) {
                'bearer-alice', 'bearer-alice-new' => 'Account belonging to Alice',
                'bearer-bob' => 'Account belonging to Bob',
                default => throw new RuntimeException('Unrecognized token'),
            };
            return ['data' => [['id' => 'cccccccc-cccc-4ccc-accc-cccccccccccc',
                'type' => 'Accounts', 'attributes' => [
                    'name' => $name, 'date_modified' => '2026-10-22',
                    'bank_c' => 'never-return-this', 'oauth_tokens' => 'never-return-this']]]];
        }
        if ($path === '/Api/V8/module/Accounts/'.$this->aliceId && $bearer === 'bearer-bob') {
            throw new RuntimeException('CRM ACL denies Bob access');
        }
        throw new RuntimeException('Test endpoint not implemented');
    }

    public function refresh(string $refreshToken): array
    {
        $this->refreshCalls++;
        if ($refreshToken !== 'refresh-alice') {
            throw new RuntimeException('Unexpected test refresh token');
        }
        return ['access_token' => 'bearer-alice-new', 'refresh_token' => 'refresh-alice-new',
                'expires_in' => 600];
    }
}

final class PersonalAccessTest extends TestCase
{
    private string $dir;
    private Config $config;
    private TokenVault $vault;
    private RecordingPersonalApi $api;
    private SuiteCrmRepository $repo;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/librecode-personal-acl-'.bin2hex(random_bytes(6));
        mkdir($this->dir, 0700, true);
        $this->config = new Config(
            suiteCrmBaseUrl: 'https://crm.example.com/legacy',
            suiteCrmClientId: 'auth-code-client',
            suiteCrmClientSecret: 'only-test-secret',
            oauthIssuer: 'https://crm.example.com/suitecrm-mcp-auth',
            mcpResourceUri: 'https://mcp.example.test/mcp',
            dataDir: $this->dir,
            encryptionKey: random_bytes(32),
            approverPublicKey: null,
            allowWrites: false,
            workflowsReviewed: false,
            allowedHosts: ['nginx'],
        );
        $this->api = new RecordingPersonalApi();
        $this->vault = new TokenVault($this->config);
        $this->vault->save('alice', $this->api->aliceId, 'bearer-alice', 'refresh-alice', time() + 3600);
        $this->vault->save('bob', $this->api->bobId, 'bearer-bob', 'refresh-bob', time() + 3600);
        $this->repo = new SuiteCrmRepository($this->api, $this->vault);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir.'/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->dir);
    }

    public function testEachMemberUsesTheirOwnSuiteCrmBearer(): void
    {
        $alice = $this->repo->listRecords('alice', 'Accounts');
        $bob = $this->repo->listRecords('bob', 'Accounts');
        self::assertSame(['bearer-alice', 'bearer-bob'], $this->api->bearers);
        self::assertSame('Account belonging to Alice', $alice['records'][0]['attributes']['name']);
        self::assertSame('Account belonging to Bob', $bob['records'][0]['attributes']['name']);
        foreach ([$alice, $bob] as $data) {
            self::assertArrayNotHasKey('bank_c', $data['records'][0]['attributes']);
            self::assertArrayNotHasKey('oauth_tokens', $data['records'][0]['attributes']);
        }
    }

    public function testRefreshedBearerIsReusedOnLaterRequests(): void
    {
        $this->vault->save('alice', $this->api->aliceId, 'bearer-alice', 'refresh-alice', time() - 5);
        $this->repo->listRecords('alice', 'Accounts');
        $this->repo->listRecords('alice', 'Accounts');
        self::assertSame(1, $this->api->refreshCalls);
        self::assertSame(['bearer-alice-new','bearer-alice-new'], $this->api->bearers);
        self::assertSame('refresh-bob', $this->vault->load('bob')['refresh_token']);
    }

    public function testMissingPersonalLinkFailsClosed(): void
    {
        $this->expectException(RuntimeException::class);
        try {
            $this->repo->listRecords('charlie', 'Accounts');
        } finally {
            self::assertSame([], $this->api->bearers);
        }
    }

    public function testSubjectToTokenIdentityMismatchIsRejected(): void
    {
        $this->vault->save('alice', $this->api->bobId, 'bearer-alice', 'refresh-alice', time() + 3600);
        $this->expectException(RuntimeException::class);
        try {
            $this->repo->listRecords('alice', 'Accounts');
        } finally {
            self::assertSame([], $this->api->bearers);
        }
    }

    public function testPersonalRefreshDoesNotUseOtherUsersSession(): void
    {
        $this->vault->save('alice', $this->api->aliceId, 'bearer-alice', 'refresh-alice', time() - 5);
        $result = $this->repo->listRecords('alice', 'Accounts');
        self::assertSame(1, $this->api->refreshCalls);
        self::assertSame(['bearer-alice-new'], $this->api->bearers);
        self::assertSame('refresh-alice-new', $this->vault->load('alice')['refresh_token']);
        self::assertSame('refresh-bob', $this->vault->load('bob')['refresh_token']);
        self::assertCount(1, $result['records']);
    }
}
