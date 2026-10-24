<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp\Tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SuiteCrmMcp\ApiClient;
use SuiteCrmMcp\Config;
use SuiteCrmMcp\LocalAuthorizationServer;
use SuiteCrmMcp\LocalTokenValidator;
use SuiteCrmMcp\TokenVault;

final class MockOAuthCrm implements ApiClient
{
    public function currentUserId(string $token): string
    {
        if ($token !== 'user-access') {
            throw new RuntimeException('unexpected bearer');
        }
        return 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa';
    }
    public function request(
        string $method,
        string $path,
        ?string $bearer = null,
        ?array $payload = null,
        array $query = []
    ): array {
        if ($method !== 'POST' || $path !== '/Api/access_token' ||
            ($payload['redirect_uri'] ?? null) !== 'https://crm.example.com/suitecrm-mcp-auth/callback' ||
            ($payload['grant_type'] ?? null) !== 'authorization_code') {
            throw new RuntimeException('unexpected CRM API operation');
        }
        return ['access_token' => 'user-access','refresh_token' => 'user-refresh','expires_in' => 600];
    }
    public function refresh(string $refreshToken): array
    {
        throw new RuntimeException('Unexpected refresh');
    }
}
final class LocalOAuthTest extends TestCase
{
    private string $dir;
    private Config $config;
    private LocalAuthorizationServer $server;
    private string $callback = 'https://chat.example.test/callback';
    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/suitecrm-oauth-test-'.bin2hex(random_bytes(5));
        mkdir($this->dir, 0700, true);
        $this->config = new Config(
            'https://crm.example.com/legacy',
            'crm-client',
            'crm-secret',
            'https://crm.example.com/suitecrm-mcp-auth',
            'https://api.openai.com/v1/mcp/tunnel_0123456789abcdef0123456789abcdef',
            $this->dir,
            random_bytes(32),
            null,
            false,
            false,
            ['nginx']
        );
        $this->server = new LocalAuthorizationServer($this->config, 'chatgpt-client', $this->callback);
    }
    protected function tearDown(): void
    {
        foreach (glob($this->dir.'/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->dir);
    }
    private function request(string $verifier): array
    {
        return ['response_type' => 'code','client_id' => 'chatgpt-client',
            'redirect_uri' => $this->callback,'scope' => 'mcp:read',
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256','resource' => 'https://api.openai.com/v1/mcp/tunnel_0123456789abcdef0123456789abcdef',
            'state' => 'client-generated-state-123456'];
    }
    public function testEndToEndWithoutSSOAndWithOneTimeCodes(): void
    {
        $verifier = str_repeat('X', 50);
        $url = $this->server->start($this->request($verifier));
        parse_str(parse_url($url, PHP_URL_QUERY), $query);
        self::assertSame('crm-client', $query['client_id']);
        $redirect = $this->server->complete($query['state'], 'synthetic-code', new MockOAuthCrm());
        parse_str(parse_url($redirect, PHP_URL_QUERY), $result);
        self::assertSame('client-generated-state-123456', $result['state']);
        $request = ['grant_type' => 'authorization_code','client_id' => 'chatgpt-client',
            'redirect_uri' => $this->callback,'resource' => 'https://api.openai.com/v1/mcp/tunnel_0123456789abcdef0123456789abcdef',
            'code' => $result['code'],'code_verifier' => $verifier];
        $tokens = $this->server->token($request);
        self::assertTrue((new LocalTokenValidator($this->config))->validate($tokens['access_token'])->isAllowed());
        self::assertSame(
            'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
            (new LocalTokenValidator($this->config))->validate($tokens['access_token'])->getAccessToken()->getSubject()
        );
        try {
            $this->server->token($request);
            self::fail('Authorization code was reused');
        } catch (RuntimeException) {
        }
        $next = $this->server->token(['grant_type' => 'refresh_token',
            'client_id' => 'chatgpt-client','resource' => 'https://api.openai.com/v1/mcp/tunnel_0123456789abcdef0123456789abcdef',
            'refresh_token' => $tokens['refresh_token']]);
        self::assertNotSame($tokens['refresh_token'], $next['refresh_token']);
        $this->expectException(RuntimeException::class);
        $this->server->token(['grant_type' => 'refresh_token','client_id' => 'chatgpt-client',
            'resource' => 'https://api.openai.com/v1/mcp/tunnel_0123456789abcdef0123456789abcdef','refresh_token' => $tokens['refresh_token']]);
    }
    public function testRevocationImmediatelyRejectsAccessAndRefreshAndBlocksRelink(): void
    {
        $verifier = str_repeat('Z', 50);
        $url = $this->server->start($this->request($verifier));
        parse_str((string) parse_url($url, PHP_URL_QUERY), $callback);
        $redirect = $this->server->complete($callback['state'], 'synthetic-code', new MockOAuthCrm());
        parse_str((string) parse_url($redirect, PHP_URL_QUERY), $query);
        $form = [
            'grant_type' => 'authorization_code',
            'client_id' => 'chatgpt-client',
            'redirect_uri' => $this->callback,
            'resource' => $this->config->mcpResourceUri,
            'code' => $query['code'],
            'code_verifier' => $verifier,
        ];
        $issued = $this->server->token($form);
        $validator = new LocalTokenValidator($this->config);
        self::assertTrue($validator->validate($issued['access_token'])->isAllowed());

        $vault = new TokenVault($this->config);
        $subject = 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa';
        $vault->revoke($subject);
        $this->server->revokeSubject($subject);
        self::assertFalse($validator->validate($issued['access_token'])->isAllowed());
        self::assertFalse($vault->linked($subject));
        self::assertTrue($vault->isBlocked($subject));
        try {
            $this->server->token([
                'grant_type' => 'refresh_token', 'client_id' => 'chatgpt-client',
                'resource' => $this->config->mcpResourceUri,
                'refresh_token' => $issued['refresh_token'],
            ]);
            self::fail('Revoked refresh should not work');
        } catch (RuntimeException $exception) {
            self::assertNotSame('', $exception->getMessage());
        }
        $this->expectException(RuntimeException::class);
        $vault->save($subject, $subject, 'synthetic-access-new', 'synthetic-refresh-new', time() + 600);
    }

    public function testUnblockRequiresRelinkAndNeverRevivesOldJwt(): void
    {
        $subject = 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa';
        $vault = new TokenVault($this->config);
        $vault->save($subject, $subject, 'synthetic-access', 'synthetic-refresh', time() + 600);
        $oldGeneration = $vault->generation($subject);
        $vault->revoke($subject);
        $vault->unblock($subject);
        self::assertFalse($vault->linked($subject));
        self::assertFalse($vault->activeAtGeneration($subject, $oldGeneration));
        $vault->save($subject, $subject, 'synthetic-new', 'synthetic-refresh-new', time() + 600);
        self::assertFalse($vault->activeAtGeneration($subject, $oldGeneration));
        self::assertTrue($vault->activeAtGeneration($subject, $vault->generation($subject)));
    }

    public function testMetadataWorksWithoutCallbackButAuthorizationFailsClosed(): void
    {
        $server = new LocalAuthorizationServer($this->config, 'chatgpt-client', '');
        self::assertSame('https://crm.example.com/suitecrm-mcp-auth', $server->metadata()['issuer']);
        $this->expectException(RuntimeException::class);
        $server->start($this->request(str_repeat('X', 50)));
    }
    public function testUnregisteredClientAndInvalidResourceFail(): void
    {
        $request = $this->request(str_repeat('X', 50));
        $request['client_id'] = 'attacker';
        $this->expectException(RuntimeException::class);
        $this->server->start($request);
    }
    public function testForgedJwtRejected(): void
    {
        self::assertFalse((new LocalTokenValidator($this->config))->validate('fake.token.value')->isAllowed());
    }
}
