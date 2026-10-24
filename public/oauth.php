<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

use SuiteCrmMcp\Config;
use SuiteCrmMcp\LocalAuthorizationServer;

require dirname(__DIR__).'/vendor/autoload.php';
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
try {
    $config = Config::fromEnvironment();
    $client = getenv('MCP_OAUTH_CLIENT_ID') ?: '';
    $redirect = getenv('MCP_OAUTH_REDIRECT_URI') ?: '';
    $server = new LocalAuthorizationServer($config, $client, $redirect);
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
    $issuerPath = parse_url($config->oauthIssuer, PHP_URL_PATH);
    $issuerHost = parse_url($config->oauthIssuer, PHP_URL_HOST);
    // Browser-facing endpoints must use the configured issuer host.
    // Private internal metadata discovery is intentionally exempt.
    if ($path !== '/oauth/token' && $path !== '/.well-known/oauth-authorization-server'.$issuerPath
        && !hash_equals((string) $issuerHost, strtolower((string) ($_SERVER['HTTP_HOST'] ?? '')))) {
        http_response_code(421);
        exit;
    }
    if ($path === '/.well-known/oauth-authorization-server'.$issuerPath
        && ($_SERVER['REQUEST_METHOD'] ?? '') === 'GET') {
        header('Content-Type: application/json');
        echo json_encode($server->metadata(), JSON_THROW_ON_ERROR);
        exit;
    }
    if ($path === $issuerPath.'/authorize' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'GET') {
        $destination = $server->start($_GET);
    } elseif ($path === $issuerPath.'/callback' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'GET') {
        $state = $_GET['state'] ?? null;
        $code = $_GET['code'] ?? null;
        if (!is_string($state) || !is_string($code) || strlen($state) > 128 ||
            strlen($code) > 4096 || $code === '') {
            throw new RuntimeException('Invalid CRM OAuth callback');
        }
        $destination = $server->complete($state, $code);
    } elseif (in_array($path, ['/oauth/token', $issuerPath.'/token'], true)
        && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
        if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 8192) {
            throw new RuntimeException('OAuth request too large');
        }
        header('Content-Type: application/json');
        $payload = $server->token($_POST);
        echo json_encode($payload, JSON_THROW_ON_ERROR);
        exit;
    } else {
        http_response_code(404);
        exit;
    }
    header('Location: '.$destination, true, 303);
} catch (Throwable $error) {
    error_log('Local OAuth broker rejected request: '.get_class($error));
    header('Content-Type: application/json');
    http_response_code(400);
    echo '{"error":"invalid_request"}';
}
