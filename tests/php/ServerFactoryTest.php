<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp\Tests;

use Mcp\Server;
use PHPUnit\Framework\TestCase;
use SuiteCrmMcp\ApprovalGate;
use SuiteCrmMcp\Config;
use SuiteCrmMcp\CrmGateway;
use SuiteCrmMcp\McpServerFactory;
use SuiteCrmMcp\Tools;

final class ServerFactoryTest extends TestCase
{
    public function testAllToolsCanBeRegisteredWithTheOfficialMcpSdk(): void
    {
        $dir = sys_get_temp_dir().'/suitecrm-mcp-schema-'.bin2hex(random_bytes(8));
        mkdir($dir, 0700, true);
        try {
            $settings = new Config(
                suiteCrmBaseUrl: 'https://crm.example.com/legacy',
                suiteCrmClientId: 'fake-id',
                suiteCrmClientSecret: 'fake-secret',
                oauthIssuer: 'https://crm.example.com/suitecrm-mcp-auth',
                mcpResourceUri: 'https://mcp.example.test/mcp',
                dataDir: $dir,
                encryptionKey: random_bytes(32),
                approverPublicKey: null,
                allowWrites: false,
                workflowsReviewed: false,
                allowedHosts: ['nginx'],
            );
            $fake = $this->createStub(CrmGateway::class);
            $tools = new Tools($fake, new ApprovalGate($settings, $fake));
            $server = McpServerFactory::build($tools, $dir.'/sessions');
            self::assertInstanceOf(Server::class, $server);
        } finally {
            foreach (glob($dir.'/*') ?: [] as $file) {
                if (is_file($file)) {
                    @unlink($file);
                }
            }
            @rmdir($dir.'/sessions');
            @rmdir($dir);
        }
    }
}
