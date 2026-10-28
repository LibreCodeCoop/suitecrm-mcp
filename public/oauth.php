<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

use SuiteCrmMcp\ApprovalGate;
use SuiteCrmMcp\BrowserApproval;
use SuiteCrmMcp\BrowserApprovalForm;
use SuiteCrmMcp\BrowserApprovalFormError;
use SuiteCrmMcp\Config;
use SuiteCrmMcp\LocalAuthorizationServer;
use SuiteCrmMcp\SuiteCrmHttp;
use SuiteCrmMcp\SuiteCrmRepository;
use SuiteCrmMcp\TokenVault;

require dirname(__DIR__).'/vendor/autoload.php';
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
try {
    $config = Config::fromEnvironment();
    $client = getenv('MCP_OAUTH_CLIENT_ID') ?: '';
    $redirect = getenv('MCP_OAUTH_REDIRECT_URI') ?: '';
    $server = new LocalAuthorizationServer($config, $client, $redirect);
    $http = new SuiteCrmHttp($config);
    $gateway = new SuiteCrmRepository($http, new TokenVault($config));
    $approvals = new BrowserApproval($config, new ApprovalGate($config, $gateway), $http);
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
    if ($path === $issuerPath.'/approve' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'GET') {
        $id = $_GET['proposal_id'] ?? null;
        if (!is_string($id)) {
            throw new RuntimeException('Missing proposal ID');
        }
        header('Location: '.$approvals->begin($id), true, 303);
        exit;
    }
    if ($path === $issuerPath.'/approve' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
        $expectedOrigin = parse_url($config->oauthIssuer, PHP_URL_SCHEME).'://'.parse_url($config->oauthIssuer, PHP_URL_HOST);
        [$ticket, $csrf] = BrowserApprovalForm::validate(
            $expectedOrigin,
            isset($_SERVER['HTTP_ORIGIN']) ? (string) $_SERVER['HTTP_ORIGIN'] : null,
            isset($_SERVER['HTTP_SEC_FETCH_SITE']) ? (string) $_SERVER['HTTP_SEC_FETCH_SITE'] : null,
            $_COOKIE['suitecrm_mcp_approval'] ?? null,
            $_POST['csrf'] ?? null
        );
        $id = $approvals->approve($ticket, $csrf);
        setcookie('suitecrm_mcp_approval', '', [
            'expires' => time() - 3600, 'path' => $issuerPath,
            'secure' => true, 'httponly' => true, 'samesite' => 'Lax',
        ]);
        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>SuiteCRM</title><body>';
        echo '<h1>Aprovação registrada</h1><p>Retorne ao ChatGPT e solicite a execução da proposta ';
        echo htmlspecialchars($id, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        echo '.</p></body></html>';
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
        if ($approvals->hasState($state)) {
            $review = $approvals->complete($state, $code);
            setcookie('suitecrm_mcp_approval', $review['ticket'], [
                'expires' => time() + 300, 'path' => $issuerPath,
                'secure' => true, 'httponly' => true, 'samesite' => 'Lax',
            ]);
            $proposal = $review['proposal']['proposal'];
            $summary = json_encode([
                'operation' => $proposal['operation'],
                'module' => $proposal['module'],
                'record_id' => $proposal['record_id'],
                'before' => $proposal['before'],
                'after' => $proposal['after'],
                'reason' => $proposal['reason'],
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
            header('Content-Type: text/html; charset=utf-8');
            header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
            echo '<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>Revisar alteração no SuiteCRM</title>';
            echo '<body style="max-width:55rem;margin:3rem auto;font:1rem system-ui;padding:1rem">';
            echo '<h1>Confirmar alteração no SuiteCRM</h1><p>Revise os dados antes de autorizar esta operação.</p><pre style="white-space:pre-wrap">';
            echo htmlspecialchars($summary, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
            echo '</pre><form method="post" action="'.htmlspecialchars($issuerPath.'/approve', ENT_QUOTES, 'UTF-8').'">';
            echo '<input type="hidden" name="csrf" value="'.htmlspecialchars($review['csrf'], ENT_QUOTES, 'UTF-8').'">';
            echo '<button type="submit">Aprovar esta operação</button></form></body></html>';
            exit;
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
    // Human browser approvals must not return a cryptic OAuth JSON error.
    // Only emit fixed, non-sensitive reason codes: never tokens, cookies,
    // authorization codes, CSRF values, subjects, or exception messages.
    if (isset($issuerPath, $path) && $path === $issuerPath.'/approve') {
        $reason = $error instanceof BrowserApprovalFormError ? $error->reason : 'approval_session_rejected';
        error_log('Browser approval rejected: '.$reason.' ('.get_class($error).')');
        http_response_code(400);
        header('Content-Type: text/html; charset=utf-8');
        header("Content-Security-Policy: default-src 'none'; base-uri 'none'; frame-ancestors 'none'");
        echo '<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>SuiteCRM: aprovação não concluída</title>';
        echo '<body><h1>Não foi possível concluir a aprovação</h1>';
        echo '<p>Nenhuma alteração foi executada. Abra novamente a proposta no ChatGPT e faça a autenticação e a aprovação no mesmo navegador.</p>';
        echo '<p>Código de diagnóstico: <code>'.htmlspecialchars($reason, ENT_QUOTES, 'UTF-8').'</code></p>';
        echo '</body></html>';
        exit;
    }

    error_log('Local OAuth broker rejected request: '.get_class($error));
    header('Content-Type: application/json');
    http_response_code(400);
    echo '{"error":"invalid_request"}';
}
