<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp;

use RuntimeException;

final readonly class Config
{
    public function __construct(
        public string $suiteCrmBaseUrl,
        public string $suiteCrmClientId,
        public string $suiteCrmClientSecret,
        public string $oauthIssuer,
        public string $mcpResourceUri,
        public string $dataDir,
        public string $encryptionKey,
        public ?string $approverPublicKey,
        public bool $allowWrites,
        public bool $workflowsReviewed,
        public array $allowedHosts,
    ) {
    }

    public static function fromEnvironment(): self
    {
        $base = rtrim(self::required('SUITECRM_BASE_URL'), '/');
        $parts = parse_url($base);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https'
            || !is_string($parts['host'] ?? null)
            || !preg_match('~^[a-z0-9.-]+$~iD', $parts['host'])
            || !preg_match('~^(?:/[A-Za-z0-9_-]+)*$~D', $parts['path'] ?? '')
            || isset($parts['user']) || isset($parts['pass'])
            || isset($parts['query']) || isset($parts['fragment'])
            || (isset($parts['port']) && $parts['port'] !== 443)) {
            throw new RuntimeException('SUITECRM_BASE_URL must be an HTTPS SuiteCRM origin with an optional path');
        }
        $resource = self::required('MCP_RESOURCE_URI');
        $issuer = rtrim(self::required('MCP_OAUTH_ISSUER'), '/');
        $issuerParts = parse_url($issuer);
        if (!is_array($issuerParts) || ($issuerParts['scheme'] ?? '') !== 'https'
            || ($issuerParts['host'] ?? null) !== $parts['host']
            || !preg_match('~^/[a-z0-9-]+$~iD', $issuerParts['path'] ?? '')
            || $issuerParts['path'] === '/oauth'
            || isset($issuerParts['user']) || isset($issuerParts['pass'])
            || isset($issuerParts['query']) || isset($issuerParts['fragment'])
            || (isset($issuerParts['port']) && $issuerParts['port'] !== 443)) {
            throw new RuntimeException('OAuth issuer must use the SuiteCRM HTTPS origin and a single dedicated path');
        }
        if (!filter_var($resource, FILTER_VALIDATE_URL) || !str_starts_with($resource, 'https://')) {
            throw new RuntimeException('MCP resource must be an HTTPS URI');
        }
        if ((getenv('APP_ENV') ?: '') === 'production') {
            $tunnelId = getenv('OPENAI_TUNNEL_ID');
            if (!is_string($tunnelId) || !preg_match('/^tunnel_(?:[a-z0-9]{4}_)?[a-z0-9]{32}$/D', $tunnelId)
                || $resource !== 'https://api.openai.com/v1/mcp/'.$tunnelId) {
                throw new RuntimeException('Production MCP resource must exactly match the configured OpenAI tunnel');
            }
        }
        $dir = self::required('MCP_DATA_DIR');
        $key = base64_decode(trim(self::secret('MCP_TOKEN_ENCRYPTION_KEY_FILE')), true);
        if (!is_string($key) || strlen($key) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
            throw new RuntimeException('Token encryption secret must contain 32 base64-decoded bytes');
        }
        $keyFile = getenv('MCP_APPROVER_PUBLIC_KEY_FILE') ?: '';
        $pub = $keyFile !== '' && is_file($keyFile) ? trim((string) file_get_contents($keyFile)) : null;
        $publicKey = $pub ? base64_decode($pub, true) : null;
        if ($publicKey !== null && (strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES)) {
            throw new RuntimeException('Approval public key is not an Ed25519 32-byte key');
        }
        return new self(
            $base,
            self::required('SUITECRM_AUTH_CLIENT_ID'),
            self::secret('SUITECRM_AUTH_CLIENT_SECRET_FILE'),
            $issuer,
            $resource,
            $dir,
            $key,
            $publicKey,
            (getenv('MCP_ALLOW_WRITES') ?: 'false') === 'true',
            (getenv('MCP_WORKFLOWS_REVIEWED') ?: 'false') === 'true',
            array_values(array_filter(array_map('trim', explode(',', getenv('MCP_ALLOWED_HOSTS') ?: 'nginx,localhost,127.0.0.1')))),
        );
    }

    private static function required(string $key): string
    {
        $value = getenv($key);
        if (!is_string($value) || trim($value) === '') {
            throw new RuntimeException('Missing configuration variable ' . $key);
        }
        return trim($value);
    }

    private static function secret(string $key): string
    {
        $path = self::required($key);
        $value = @file_get_contents($path);
        if (!is_string($value) || trim($value) === '') {
            throw new RuntimeException('Missing required secret file for ' . $key);
        }
        return trim($value);
    }
}
