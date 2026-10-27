<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp;

use RuntimeException;

final class SuiteCrmHttp implements ApiClient
{
    public function __construct(private readonly Config $config)
    {
    }

    /**
     * All URLs are built from a validated SuiteCRM host. Tokens and response
     * bodies must never enter logs or MCP tool errors.
     */
    public function request(
        string $method,
        string $path,
        ?string $bearer = null,
        ?array $payload = null,
        array $query = []
    ): array {
        if (!in_array($method, ['GET', 'POST', 'PATCH', 'DELETE'], true) ||
            !preg_match('~^/Api/(?:access_token|V8/[A-Za-z0-9_/\\-]+)$~D', $path) ||
            str_contains($path, '//') || str_contains($path, '..') ||
            in_array($method, ['POST', 'PATCH'], true) && $payload === null) {
            throw new RuntimeException('Invalid SuiteCRM API operation');
        }
        if ($path === '/Api/access_token' && ($method !== 'POST' || $bearer !== null)) {
            throw new RuntimeException('OAuth endpoint requires password or refresh grant');
        }
        if ($path !== '/Api/access_token' && ($bearer === null || $bearer === '')) {
            throw new RuntimeException('SuiteCRM request requires a personal bearer token');
        }
        if ($query !== [] && $method !== 'GET') {
            throw new RuntimeException('Query parameters only allowed on GET');
        }
        $url = $this->config->suiteCrmBaseUrl.$path.
            ($query === [] ? '' : '?'.http_build_query($query, '', '&', PHP_QUERY_RFC3986));
        $handle = curl_init($url);
        if ($handle === false) {
            throw new RuntimeException('Cannot initialize the SuiteCRM HTTP client');
        }
        try {
            // SuiteCRM OAuth expects ordinary JSON; API V8 uses JSON:API media types.
            $isOAuth = $path === '/Api/access_token';
            $headers = [
                $isOAuth ? 'Accept: application/json' : 'Accept: application/vnd.api+json',
                $isOAuth ? 'Content-Type: application/json' : 'Content-Type: application/vnd.api+json',
                'User-Agent: SuiteCRM-MCP-PHP/0.5',
            ];
            if ($bearer !== null) {
                $headers[] = 'Authorization: Bearer '.$bearer;
            }
            $body = null;
            if ($payload !== null) {
                $body = json_encode($payload, JSON_THROW_ON_ERROR);
                if (strlen($body) > 25000) {
                    throw new RuntimeException('SuiteCRM request is too large');
                }
            }
            curl_setopt_array($handle, [
                CURLOPT_CUSTOMREQUEST => $method,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_MAXREDIRS => 0,
                CURLOPT_CONNECTTIMEOUT => 6,
                CURLOPT_TIMEOUT => 20,
                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
            ]);
            if ($body !== null) {
                curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
            }
            $raw = curl_exec($handle);
            $status = curl_getinfo($handle, CURLINFO_HTTP_CODE);
            if (!is_string($raw) || strlen($raw) > 2_000_000 || $status < 200 || $status >= 300) {
                // Do not leak CRM response bodies or request credentials.
                throw new RuntimeException('SuiteCRM HTTP request rejected, status '.($status ?: 'unavailable'));
            }
            if ($raw === '' && $method === 'DELETE') {
                return [];
            }
            $value = json_decode($raw, true, 128, JSON_THROW_ON_ERROR);
            if (!is_array($value)) {
                throw new RuntimeException('Malformed SuiteCRM API JSON');
            }
            return $value;
        } finally {
            curl_close($handle);
        }
    }

    public function refresh(string $refreshToken): array
    {
        return $this->request('POST', '/Api/access_token', payload: [
            'grant_type' => 'refresh_token',
            'client_id' => $this->config->suiteCrmClientId,
            'client_secret' => $this->config->suiteCrmClientSecret,
            'refresh_token' => $refreshToken,
        ]);
    }

    public function currentUserId(string $token): string
    {
        $payload = $this->request('GET', '/Api/V8/current-user', bearer: $token);
        $data = $payload['data'] ?? [];
        if (!is_array($data)) {
            throw new RuntimeException('SuiteCRM identity response invalid');
        }
        $id = $data['id'] ?? $data['attributes']['id'] ?? null;
        if (!is_string($id)) {
            throw new RuntimeException('SuiteCRM user ID unavailable');
        }
        return Policy::recordId($id);
    }
}
