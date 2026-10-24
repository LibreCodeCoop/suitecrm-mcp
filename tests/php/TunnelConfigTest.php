<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp\Tests;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SuiteCrmMcp\Config;

final class TunnelConfigTest extends TestCase
{
    private string $dir;
    /** @var array<string, string|false> */
    private array $previous = [];

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/suitecrm-tunnel-config-'.bin2hex(random_bytes(6));
        mkdir($this->dir, 0700, true);
        file_put_contents($this->dir.'/encryption', base64_encode(random_bytes(32)));
        file_put_contents($this->dir.'/oauth-client-secret', 'synthetic-only');
        $values = [
            'APP_ENV' => 'production',
            'SUITECRM_BASE_URL' => 'https://crm.example.com/legacy',
            'SUITECRM_AUTH_CLIENT_ID' => 'synthetic-client',
            'SUITECRM_AUTH_CLIENT_SECRET_FILE' => $this->dir.'/oauth-client-secret',
            'MCP_OAUTH_ISSUER' => 'https://crm.example.com/suitecrm-mcp-auth',
            'MCP_RESOURCE_URI' => 'https://api.openai.com/v1/mcp/tunnel_0123456789abcdef0123456789abcdef',
            'OPENAI_TUNNEL_ID' => 'tunnel_0123456789abcdef0123456789abcdef',
            'MCP_DATA_DIR' => $this->dir,
            'MCP_TOKEN_ENCRYPTION_KEY_FILE' => $this->dir.'/encryption',
            'MCP_APPROVER_PUBLIC_KEY_FILE' => '',
            'MCP_ALLOW_WRITES' => 'false',
            'MCP_WORKFLOWS_REVIEWED' => 'false',
        ];
        foreach ($values as $name => $value) {
            $this->previous[$name] = getenv($name);
            putenv($name.'='.$value);
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->previous as $key => $old) {
            if ($old === false) {
                putenv($key);
            } else {
                putenv($key.'='.$old);
            }
        }
        foreach (glob($this->dir.'/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->dir);
    }

    public function testExactTunnelResourceAndIssuerAreRequired(): void
    {
        $config = Config::fromEnvironment();
        self::assertSame('https://crm.example.com/suitecrm-mcp-auth', $config->oauthIssuer);
        self::assertSame(
            'https://api.openai.com/v1/mcp/tunnel_0123456789abcdef0123456789abcdef',
            $config->mcpResourceUri
        );
        self::assertFalse($config->allowWrites);
        self::assertFalse($config->workflowsReviewed);
    }

    public function testAnyConfiguredHttpsSuiteCrmHostAndIssuerPathAreSupported(): void
    {
        putenv('SUITECRM_BASE_URL=https://crm.other-example.net/suitecrm');
        putenv('MCP_OAUTH_ISSUER=https://crm.other-example.net/oauth-broker');
        $config = Config::fromEnvironment();

        self::assertSame('https://crm.other-example.net/suitecrm', $config->suiteCrmBaseUrl);
        self::assertSame('https://crm.other-example.net/oauth-broker', $config->oauthIssuer);
    }

    public function testIssuerCannotShadowThePrivateOauthTokenRoute(): void
    {
        putenv('MCP_OAUTH_ISSUER=https://crm.example.com/oauth');
        $this->expectException(RuntimeException::class);
        Config::fromEnvironment();
    }

    public function testInsecureSuiteCrmBaseUrlIsRejected(): void
    {
        putenv('SUITECRM_BASE_URL=http://crm.example.com');
        $this->expectException(RuntimeException::class);
        Config::fromEnvironment();
    }

    public function testIncorrectTunnelAudienceFailsClosed(): void
    {
        putenv('MCP_RESOURCE_URI=https://api.openai.com/v1/mcp/tunnel_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
        $this->expectException(RuntimeException::class);
        Config::fromEnvironment();
    }

    public function testWrongIssuerDomainFailsClosed(): void
    {
        putenv('MCP_OAUTH_ISSUER=https://attacker.example.test/suitecrm-mcp-auth');
        $this->expectException(RuntimeException::class);
        Config::fromEnvironment();
    }

    public function testMalformedTunnelIdFailsClosed(): void
    {
        putenv('OPENAI_TUNNEL_ID=not-a-tunnel-id');
        $this->expectException(RuntimeException::class);
        Config::fromEnvironment();
    }
}
