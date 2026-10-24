<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

use Mcp\Server\Transport\Http\Middleware\AuthorizationMiddleware;
use Mcp\Server\Transport\Http\Middleware\CorsMiddleware;
use Mcp\Server\Transport\Http\Middleware\DnsRebindingProtectionMiddleware;
use Mcp\Server\Transport\Http\Middleware\ProtectedResourceMetadataMiddleware;
use Mcp\Server\Transport\Http\OAuth\ProtectedResourceMetadata;
use Mcp\Server\Transport\Http\OAuth\ScopePolicy;
use Mcp\Server\Transport\StreamableHttpTransport;
use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;
use SuiteCrmMcp\ApprovalGate;
use SuiteCrmMcp\Config;
use SuiteCrmMcp\LocalTokenValidator;
use SuiteCrmMcp\McpServerFactory;
use SuiteCrmMcp\SuiteCrmHttp;
use SuiteCrmMcp\SuiteCrmRepository;
use SuiteCrmMcp\TokenVault;
use SuiteCrmMcp\Tools;

require dirname(__DIR__).'/vendor/autoload.php';

try {
    $config = Config::fromEnvironment();
    $psr17 = new Psr17Factory();
    $request = (new ServerRequestCreator($psr17, $psr17, $psr17, $psr17))->fromGlobals();
    // Dedicated, audience-bound MCP tokens are issued by the local PHP broker.
    $validator = new LocalTokenValidator($config);
    // OAuth must advertise the same public resource and issuer used by
    // ChatGPT, or its OAuth resource parameter cannot match issued tokens.
    // The MCP transport remains private: no incoming Internet port is opened.
    $metadata = new ProtectedResourceMetadata(
        resource: $config->mcpResourceUri,
        authorizationServers: [$config->oauthIssuer],
        scopesSupported: ['mcp:read'],
    );
    // tunnel-client discovers metadata at the private transport path /mcp,
    // while the canonical RFC 9728 path is derived from the hosted resource.
    // Alias only this metadata GET; all other requests preserve their URI.
    if ($request->getMethod() === 'GET'
        && $request->getUri()->getPath() === '/.well-known/oauth-protected-resource/mcp') {
        $request = $request->withUri(
            $request->getUri()->withPath($metadata->getMetadataPath())
        );
    }
    $transport = new StreamableHttpTransport(
        request: $request,
        responseFactory: $psr17,
        streamFactory: $psr17,
        middleware: [
            new CorsMiddleware(allowedOrigins: []),
            new DnsRebindingProtectionMiddleware(allowedHosts: $config->allowedHosts),
            new ProtectedResourceMetadataMiddleware($metadata),
            new AuthorizationMiddleware(
                $validator,
                $metadata,
                new ScopePolicy(default: ['mcp:read'])
            ),
        ],
    );

    $http = new SuiteCrmHttp($config);
    $vault = new TokenVault($config);
    $crm = new SuiteCrmRepository($http, $vault);
    $approvals = new ApprovalGate($config, $crm);
    $tools = new Tools($crm, $approvals);
    // Tool registry is isolated in a testable factory.
    $response = McpServerFactory::build(
        $tools,
        $config->dataDir.'/mcp-sessions',
        $config->allowWrites && $config->workflowsReviewed
    )->run($transport);
    // The HTTP transport returns a PSR-7 response.
    http_response_code($response->getStatusCode());
    foreach ($response->getHeaders() as $key => $values) {
        foreach ($values as $value) {
            header($key.': '.$value, false);
        }
    }
    echo (string) $response->getBody();
} catch (\Throwable $error) {
    // Never echo raw exception messages, URLs, claims, tokens or user records.
    error_log('MCP internal error: '.get_class($error));
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: application/json');
        header('Cache-Control: no-store');
    }
    echo '{"error":"Internal MCP failure; review server logs"}';
}
