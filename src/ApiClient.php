<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp;

/** Narrow API client interface for personal-token security tests. */
interface ApiClient
{
    public function request(
        string $method,
        string $path,
        ?string $bearer = null,
        ?array $payload = null,
        array $query = []
    ): array;

    public function refresh(string $refreshToken): array;

    public function currentUserId(string $token): string;
}
