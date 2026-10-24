<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp\Tests;

use Firebase\JWT\JWT;
use Mcp\Server\Transport\Http\OAuth\ProtectedResourceMetadata;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SuiteCrmMcp\Config;
use SuiteCrmMcp\LocalAuthorizationServer;
use SuiteCrmMcp\LocalTokenValidator;
use SuiteCrmMcp\TokenVault;

final class TunnelOAuthTest extends TestCase
{
    private const RESOURCE = 'https://api.openai.com/v1/mcp/tunnel_0123456789abcdef0123456789abcdef';
    private const ISSUER = 'https://crm.example.com/suitecrm-mcp-auth';
    private string $dir;
    private Config $config;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/librecode-tunnel-oauth-'.bin2hex(random_bytes(8));
        mkdir($this->dir, 0700, true);
        $this->config = new Config(
            'https://crm.example.com/legacy',
            'crm-client',
            'fake-local-only',
            self::ISSUER,
            self::RESOURCE,
            $this->dir,
            random_bytes(32),
            null,
            false,
            false,
            ['127.0.0.1'],
        );
    }
    protected function tearDown(): void
    {
        foreach (glob($this->dir.'/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->dir);
    }

    public function testOAuthMetadataUsesPublicTokenAndPrivateMcpResource(): void
    {
        $server = new LocalAuthorizationServer($this->config, 'chatgpt-client', 'https://chatgpt.com/callback');
        $metadata = $server->metadata();
        self::assertSame(self::ISSUER, $metadata['issuer']);
        self::assertSame(self::ISSUER.'/authorize', $metadata['authorization_endpoint']);
        self::assertSame(self::ISSUER.'/token', $metadata['token_endpoint']);
        self::assertContains('S256', $metadata['code_challenge_methods_supported']);
        self::assertSame(['none'], $metadata['token_endpoint_auth_methods_supported']);
        // Canonical RFC 9728 identifiers MUST be the same resource/issuer
        // used by ChatGPT, never the private Docker loopback transport.
        $prmd = new ProtectedResourceMetadata(self::RESOURCE, [self::ISSUER], ['mcp:read']);
        self::assertSame(self::RESOURCE, $prmd->jsonSerialize()['resource']);
        self::assertSame([self::ISSUER], $prmd->jsonSerialize()['authorization_servers']);
        self::assertSame(
            '/.well-known/oauth-protected-resource/v1/mcp/tunnel_0123456789abcdef0123456789abcdef',
            $prmd->getMetadataPath()
        );
    }

    public function testTokenCannotBeUsedWithWrongIssuerAudienceScopeOrExpiry(): void
    {
        $validator = new LocalTokenValidator($this->config);
        $vault = new TokenVault($this->config);
        $subject = 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa';
        $vault->save($subject, $subject, 'synthetic-access', 'synthetic-refresh', time() + 600);
        $now = time();
        $good = [
            'iss' => self::ISSUER, 'aud' => self::RESOURCE,
            'sub' => 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
            'token_use' => 'access', 'scope' => 'mcp:read',
            'generation' => $vault->generation($subject),
            'iat' => $now - 60, 'nbf' => $now - 60, 'exp' => $now + 60,
        ];
        $key = LocalTokenValidator::signingKey($this->config);
        self::assertTrue($validator->validate(JWT::encode($good, $key, 'HS256'))->isAllowed());
        foreach ([
            ['iss' => 'https://imposter.example.test'],
            ['aud' => 'https://crm.example.com/legacy'],
            ['scope' => 'mcp:write'],
            ['token_use' => 'refresh'],
            ['exp' => $now - 2],
        ] as $override) {
            self::assertFalse($validator->validate(
                JWT::encode(array_replace($good, $override), $key, 'HS256')
            )->isAllowed());
        }
    }

    public function testOAuthStartRejectsNonTunnelResourceAndUnregisteredRedirect(): void
    {
        $server = new LocalAuthorizationServer($this->config, 'chatgpt-client', 'https://chatgpt.com/callback');
        $request = [
            'response_type' => 'code', 'client_id' => 'chatgpt-client',
            'redirect_uri' => 'https://chatgpt.com/callback',
            'state' => 'sufficient-entropy-state-012345',
            'scope' => 'mcp:read', 'resource' => self::RESOURCE,
            'code_challenge_method' => 'S256',
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', str_repeat('a', 48), true)), '+/', '-_'), '='),
        ];
        foreach ([
            ['resource' => 'https://crm.example.com/legacy'],
            ['redirect_uri' => 'https://attacker.example.test/callback'],
            ['code_challenge_method' => 'plain'],
            ['scope' => 'mcp:write'],
        ] as $override) {
            try {
                $server->start(array_replace($request, $override));
                self::fail('Invalid authorization request was accepted');
            } catch (RuntimeException) {
                self::assertTrue(true);
            }
        }
        $url = $server->start($request);
        self::assertStringStartsWith('https://crm.example.com/legacy/Api/authorize?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $params);
        self::assertSame(self::ISSUER.'/callback', $params['redirect_uri']);
    }
}
