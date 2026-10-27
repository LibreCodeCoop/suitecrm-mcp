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

final class SyntheticModuleClient implements ApiClient
{
    public array $calls = [];

    public function request(string $method, string $path, ?string $bearer = null, ?array $payload = null, array $query = []): array
    {
        $this->calls[] = compact('method', 'path', 'bearer', 'payload', 'query');
        if ($bearer !== 'synthetic-access') {
            throw new RuntimeException('Wrong user token');
        }
        return ['data' => [['type' => 'Accounts', 'id' => '11111111-2222-4333-a444-555555555555',
            'attributes' => ['id' => '11111111-2222-4333-a444-555555555555', 'name' => 'Test']]]];
    }

    public function currentUserId(string $token): string
    {
        return 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa';
    }

    public function refresh(string $refreshToken): array
    {
        throw new RuntimeException('No refresh expected');
    }
}

final class ModuleApiTest extends TestCase
{
    private string $dir;
    private SyntheticModuleClient $client;
    private SuiteCrmRepository $repo;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/mcp-module-test-'.bin2hex(random_bytes(7));
        mkdir($this->dir, 0700, true);
        $config = new Config(
            'https://crm.example.com/legacy',
            'test',
            'test',
            'https://crm.example.com/suitecrm-mcp-auth',
            'https://mcp.example.test',
            $this->dir,
            random_bytes(32),
            null,
            true,
            true,
            ['nginx']
        );
        $vault = new TokenVault($config);
        $vault->save(
            'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
            'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
            'synthetic-access',
            'synthetic-refresh',
            time() + 500
        );
        $this->client = new SyntheticModuleClient();
        $this->repo = new SuiteCrmRepository($this->client, $vault);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir.'/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->dir);
    }

    public function testDeleteUsesOnlyPersonalTokenAndCanonicalV8Endpoint(): void
    {
        $recordId = '11111111-2222-4333-a444-555555555555';
        $result = $this->repo->writeApproved(
            'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
            'delete',
            'Accounts',
            [],
            $recordId
        );
        self::assertSame($recordId, $result['record_id']);
        self::assertSame('DELETE', $this->client->calls[0]['method']);
        self::assertSame('/Api/V8/module/Accounts/'.$recordId, $this->client->calls[0]['path']);
        self::assertSame('synthetic-access', $this->client->calls[0]['bearer']);
        self::assertNull($this->client->calls[0]['payload']);
    }

    public function testSearchUsesServerSideExactFiltersAndSupportsPagination(): void
    {
        $this->repo->searchRecords(
            'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
            'Accounts',
            'name',
            'OCB/RJ',
            6,
            10
        );
        self::assertSame('OCB/RJ', $this->client->calls[0]['query']['filter[name][eq]']);
        self::assertSame(6, $this->client->calls[0]['query']['page[number]']);
    }

    public function testRelationshipOperationsUseExactDocumentedV8Endpoints(): void
    {
        $subject = 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa';
        $source = '11111111-2222-4333-a444-555555555555';
        $target = 'bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb';
        $this->repo->writeRelationship(
            $subject,
            'link',
            'Accounts',
            $source,
            'contacts',
            'Contacts',
            $target
        );
        self::assertSame('POST', $this->client->calls[0]['method']);
        self::assertSame(
            '/Api/V8/module/Accounts/'.$source.'/relationships/contacts',
            $this->client->calls[0]['path']
        );
        self::assertSame(
            ['data' => ['type' => 'Contacts', 'id' => $target]],
            $this->client->calls[0]['payload']
        );
        $this->repo->writeRelationship(
            $subject,
            'unlink',
            'Accounts',
            $source,
            'contacts',
            'Contacts',
            $target
        );
        self::assertSame('DELETE', $this->client->calls[1]['method']);
        self::assertSame(
            '/Api/V8/module/Accounts/'.$source.'/relationships/contacts/'.$target,
            $this->client->calls[1]['path']
        );
    }

    public function testArbitraryFilterFieldIsRejectedBeforeHttpCall(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->repo->searchRecords(
            'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
            'Accounts',
            'password',
            'irrelevant'
        );
    }
}
