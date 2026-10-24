<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp;

/** Stable seam between MCP tools, approval policy and per-user SuiteCRM API. */
interface CrmGateway
{
    public function linked(string $subject): bool;
    public function modules(string $subject): array;
    public function schema(string $subject, string $module): array;
    public function listRecords(string $subject, string $module, array $fields = [], int $page = 1, int $pageSize = 10): array;
    public function getRecord(string $subject, string $module, string $recordId, array $fields = []): array;
    public function getRawForDiff(string $subject, string $module, string $id, array $fields): array;
    public function writeApproved(string $subject, string $method, string $module, array $attrs, ?string $id): array;
}
