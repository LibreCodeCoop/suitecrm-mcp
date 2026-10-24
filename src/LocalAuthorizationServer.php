<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp;

use Firebase\JWT\JWT;
use PDO;
use RuntimeException;

/**
 * Local OAuth Authorization Code + PKCE broker. SuiteCRM authenticates the user;
 * this broker issues audience-bound MCP tokens, never SuiteCRM credentials.
 */
final class LocalAuthorizationServer
{
    private PDO $db;
    public function __construct(
        private readonly Config $config,
        private readonly string $clientId,
        private readonly string $redirectUri
    ) {
        // Discovery can run before the ChatGPT plugin reveals its callback.
        // Interactive authorization remains fail-closed until an exact HTTPS
        // callback is configured by an administrator.
        if ($clientId === '' || ($redirectUri !== '' && (
            !filter_var($redirectUri, FILTER_VALIDATE_URL)
            || !str_starts_with($redirectUri, 'https://')
        ))) {
            throw new RuntimeException('Registered OAuth client is invalid');
        }
        $this->db = new PDO('sqlite:'.$config->dataDir.'/oauth.sqlite3');
        $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        @chmod($config->dataDir.'/oauth.sqlite3', 0600);
        $this->db->exec('PRAGMA busy_timeout=3000');
        $this->db->exec('CREATE TABLE IF NOT EXISTS authorizations (
            digest TEXT PRIMARY KEY, subject TEXT, client TEXT NOT NULL, redirect TEXT NOT NULL,
            challenge TEXT NOT NULL, state TEXT NOT NULL, expires INTEGER NOT NULL
        )');
        $this->db->exec('CREATE TABLE IF NOT EXISTS refresh_tokens (
            digest TEXT PRIMARY KEY, subject TEXT NOT NULL, client TEXT NOT NULL,
            expires INTEGER NOT NULL
        )');
    }

    public function issuer(): string
    {
        return $this->config->oauthIssuer;
    }
    public function metadata(): array
    {
        $issuer = $this->issuer();
        // The OAuth authorization server uses the existing SuiteCRM HTTPS origin.
        // Its strictly POST-only token endpoint is public; the MCP endpoint
        // itself stays private behind Secure MCP Tunnel.
        $tokenEndpoint = $issuer.'/token';
        return [
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer.'/authorize',
            'token_endpoint' => $tokenEndpoint,
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['none'],
            'scopes_supported' => ['mcp:read'],
        ];
    }
    private static function digest(string $token): string
    {
        return hash('sha256', $token);
    }
    private static function random(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }
    private function requireClient(string $client, string $redirect): void
    {
        if ($this->redirectUri === '' || !hash_equals($this->clientId, $client)
            || !hash_equals($this->redirectUri, $redirect)) {
            throw new RuntimeException('Unregistered OAuth client or redirect URI');
        }
    }
    public function start(array $query): string
    {
        $client = $query['client_id'] ?? null;
        $redirect = $query['redirect_uri'] ?? null;
        $challenge = $query['code_challenge'] ?? null;
        $state = $query['state'] ?? null;
        if (!is_string($client) || !is_string($redirect) ||
            !is_string($challenge) || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $challenge) ||
            ($query['code_challenge_method'] ?? null) !== 'S256' ||
            ($query['response_type'] ?? null) !== 'code' ||
            !is_string($state) || strlen($state) < 16 || strlen($state) > 512 ||
            ($query['resource'] ?? null) !== $this->config->mcpResourceUri ||
            !in_array(($query['scope'] ?? ''), ['mcp:read'], true)) {
            throw new RuntimeException('Invalid OAuth authorization request');
        }
        $this->requireClient($client, $redirect);
        $nonce = self::random();
        $this->db->prepare('DELETE FROM authorizations WHERE expires < ?')->execute([time()]);
        $this->db->prepare('DELETE FROM refresh_tokens WHERE expires < ?')->execute([time()]);
        $sql = $this->db->prepare('INSERT INTO authorizations VALUES (?,NULL,?,?,?,?,?)');
        $sql->execute([self::digest($nonce), $client, $redirect, $challenge, $state, time() + 300]);
        return $this->config->suiteCrmBaseUrl.'/Api/authorize?'.http_build_query([
            'response_type' => 'code',
            'client_id' => $this->config->suiteCrmClientId,
            'redirect_uri' => $this->callbackUri(),
            'state' => $nonce,
        ], '', '&', PHP_QUERY_RFC3986);
    }
    private function callbackUri(): string
    {
        return $this->issuer().'/callback';
    }
    public function complete(string $state, string $crmCode, ?ApiClient $http = null): string
    {
        $digest = self::digest($state);
        $this->db->beginTransaction();
        try {
            $q = $this->db->prepare('SELECT * FROM authorizations WHERE digest=? AND subject IS NULL AND expires>?');
            $q->execute([$digest, time()]);
            $entry = $q->fetch(PDO::FETCH_ASSOC);
            if (!is_array($entry)) {
                throw new RuntimeException('Invalid or expired OAuth state');
            }
            $this->db->prepare('DELETE FROM authorizations WHERE digest=?')->execute([$digest]);
            $this->db->commit();
        } catch (\Throwable $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            throw $e;
        }
        $http ??= new SuiteCrmHttp($this->config);
        $tokens = $http->request('POST', '/Api/access_token', payload: [
            'grant_type' => 'authorization_code',
            'client_id' => $this->config->suiteCrmClientId,
            'client_secret' => $this->config->suiteCrmClientSecret,
            'code' => $crmCode,
            'redirect_uri' => $this->callbackUri(),
        ]);
        $access = $tokens['access_token'] ?? null;
        $refresh = $tokens['refresh_token'] ?? null;
        if (!is_string($access) || $access === '' || !is_string($refresh) || $refresh === '') {
            throw new RuntimeException('CRM authentication failed');
        }
        $subject = $http->currentUserId($access);
        (new TokenVault($this->config))->save(
            $subject,
            $subject,
            $access,
            $refresh,
            time() + max(30, (int)($tokens['expires_in'] ?? 600))
        );
        $code = self::random();
        $this->db->prepare('INSERT INTO authorizations VALUES (?,?,?,?,?,?,?)')
            ->execute([self::digest($code), $subject, $entry['client'], $entry['redirect'],
                       $entry['challenge'], $entry['state'], time() + 120]);
        return $entry['redirect'].'?'.http_build_query([
            'code' => $code, 'state' => $entry['state']
        ], '', '&', PHP_QUERY_RFC3986);
    }
    public function token(array $form): array
    {
        $client = $form['client_id'] ?? null;
        if (!is_string($client) || !hash_equals($this->clientId, $client) ||
            ($form['resource'] ?? null) !== $this->config->mcpResourceUri) {
            throw new RuntimeException('Invalid OAuth client or resource');
        }
        $grant = $form['grant_type'] ?? '';
        if ($grant === 'authorization_code') {
            $code = $form['code'] ?? null;
            $verifier = $form['code_verifier'] ?? null;
            $redirect = $form['redirect_uri'] ?? null;
            if (!is_string($code) || !is_string($verifier) ||
                !preg_match('/^[A-Za-z0-9._~-]{43,128}$/D', $verifier) || !is_string($redirect)) {
                throw new RuntimeException('Invalid authorization code request');
            }
            $this->requireClient($client, $redirect);
            $this->db->beginTransaction();
            try {
                $q = $this->db->prepare('SELECT * FROM authorizations WHERE digest=? AND subject IS NOT NULL AND expires>?');
                $q->execute([self::digest($code), time()]);
                $row = $q->fetch(PDO::FETCH_ASSOC);
                $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
                if (!is_array($row) || !hash_equals($row['challenge'], $challenge) ||
                    !hash_equals($row['client'], $client) || !hash_equals($row['redirect'], $redirect)) {
                    throw new RuntimeException('Invalid authorization code or PKCE');
                }
                $this->db->prepare('DELETE FROM authorizations WHERE digest=?')->execute([self::digest($code)]);
                $this->db->commit();
            } catch (\Throwable $e) {
                if ($this->db->inTransaction()) {
                    $this->db->rollBack();
                }
                throw $e;
            }
            return $this->issue($row['subject'], $client);
        }
        if ($grant === 'refresh_token') {
            $refresh = $form['refresh_token'] ?? null;
            if (!is_string($refresh)) {
                throw new RuntimeException('Missing refresh token');
            }
            $this->db->beginTransaction();
            try {
                $q = $this->db->prepare('SELECT * FROM refresh_tokens WHERE digest=? AND expires>? AND client=?');
                $q->execute([self::digest($refresh),time(),$client]);
                $row = $q->fetch(PDO::FETCH_ASSOC);
                if (!is_array($row)) {
                    throw new RuntimeException('Refresh token is invalid');
                }
                $this->db->prepare('DELETE FROM refresh_tokens WHERE digest=?')->execute([self::digest($refresh)]);
                $this->db->commit();
            } catch (\Throwable $e) {
                if ($this->db->inTransaction()) {
                    $this->db->rollBack();
                }
                throw $e;
            }
            return $this->issue($row['subject'], $client);
        }
        throw new RuntimeException('Unsupported grant type');
    }
    /** Administrator-only: the vault deny-list is the authoritative gate. */
    public function revokeSubject(string $subject): void
    {
        TokenVault::subject($subject);
        $this->db->beginTransaction();
        try {
            $this->db->prepare('DELETE FROM refresh_tokens WHERE subject=?')->execute([$subject]);
            $this->db->prepare('DELETE FROM authorizations WHERE subject=?')->execute([$subject]);
            $this->db->commit();
        } catch (\Throwable $e) {
            $this->db->rollBack();
            throw $e;
        }
    }

    private function issue(string $subject, string $client): array
    {
        $vault = new TokenVault($this->config);
        if (!$vault->linked($subject) || $vault->isBlocked($subject)) {
            throw new RuntimeException('Personal SuiteCRM account is not active');
        }
        $generation = $vault->generation($subject);
        $now = time();
        $token = JWT::encode([
            'iss' => $this->issuer(), 'aud' => $this->config->mcpResourceUri, 'sub' => $subject,
            'client_id' => $client, 'scope' => 'mcp:read', 'token_use' => 'access',
            'generation' => $generation,
            'iat' => $now, 'nbf' => $now, 'exp' => $now + 600, 'jti' => self::random(),
        ], LocalTokenValidator::signingKey($this->config), 'HS256');
        $refresh = self::random();
        $this->db->prepare('INSERT INTO refresh_tokens VALUES (?,?,?,?)')
            ->execute([self::digest($refresh),$subject,$client,$now + 86400 * 7]);
        return ['access_token' => $token,'token_type' => 'Bearer',
            'expires_in' => 600,'scope' => 'mcp:read','refresh_token' => $refresh];
    }
}
