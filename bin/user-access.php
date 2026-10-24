<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

use SuiteCrmMcp\Config;
use SuiteCrmMcp\LocalAuthorizationServer;
use SuiteCrmMcp\TokenVault;

require dirname(__DIR__).'/vendor/autoload.php';

$argv = $_SERVER['argv'] ?? [];

if (PHP_SAPI !== 'cli' || count($argv) !== 4 || $argv[1] !== '--confirm'
    || !in_array($argv[2], ['revoke', 'unblock'], true)) {
    fwrite(STDERR, "Usage: php bin/user-access.php --confirm revoke|unblock <suitecrm-user-uuid>\n");
    exit(2);
}

try {
    $config = Config::fromEnvironment();
    $subject = TokenVault::subject($argv[3]);
    // The subject must be a SuiteCRM user UUID, not an arbitrary ChatGPT identity.
    if (!preg_match('/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/iD', $subject)) {
        throw new RuntimeException('Invalid SuiteCRM user UUID');
    }
    $vault = new TokenVault($config);
    if ($argv[2] === 'revoke') {
        // Fail closed even if removing OAuth refresh tokens subsequently fails.
        $vault->revoke($subject);
        $broker = new LocalAuthorizationServer(
            $config,
            getenv('MCP_OAUTH_CLIENT_ID') ?: '',
            getenv('MCP_OAUTH_REDIRECT_URI') ?: ''
        );
        $broker->revokeSubject($subject);
        fwrite(STDOUT, "MCP identity blocked and tokens invalidated.\n");
    } else {
        $vault->unblock($subject);
        fwrite(STDOUT, "MCP identity unblocked. A fresh personal login is required.\n");
    }
} catch (Throwable $error) {
    // Never log user credentials, OAuth token strings or internal exception details.
    fwrite(STDERR, 'Unable to change MCP account status: '.get_class($error)."\n");
    exit(1);
}
