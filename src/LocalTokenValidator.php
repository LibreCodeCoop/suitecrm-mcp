<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Mcp\Server\Authorization\AccessToken;
use Mcp\Server\Transport\Http\OAuth\AuthorizationResult;
use Mcp\Server\Transport\Http\OAuth\AuthorizationTokenValidatorInterface;

final class LocalTokenValidator implements AuthorizationTokenValidatorInterface
{
    public function __construct(private readonly Config $config)
    {
    }

    public static function signingKey(Config $config): string
    {
        return hash_hkdf('sha256', $config->encryptionKey, 32, 'librecode-mcp-oauth-signing-v1');
    }

    public function validate(string $accessToken): AuthorizationResult
    {
        try {
            $claims = (array) JWT::decode($accessToken, new Key(self::signingKey($this->config), 'HS256'));
            if (($claims['iss'] ?? null) !== $this->config->oauthIssuer
                || ($claims['aud'] ?? null) !== $this->config->mcpResourceUri
                || ($claims['token_use'] ?? null) !== 'access'
                || !is_string($claims['sub'] ?? null)
                || !is_string($claims['scope'] ?? null)
                || !in_array('mcp:read', explode(' ', $claims['scope']), true)) {
                return AuthorizationResult::unauthorized('invalid_token');
            }
            TokenVault::subject($claims['sub']);
            if (!is_int($claims['generation'] ?? null)
                || !(new TokenVault($this->config))->activeAtGeneration(
                    $claims['sub'],
                    $claims['generation']
                )) {
                return AuthorizationResult::unauthorized('invalid_token');
            }
            return AuthorizationResult::allow(new AccessToken(explode(' ', $claims['scope']), $claims));
        } catch (\Throwable) {
            return AuthorizationResult::unauthorized('invalid_token');
        }
    }
}
