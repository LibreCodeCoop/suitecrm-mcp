<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp;

use RuntimeException;

/** Fixed, safe error labels (never include credentials, cookies or CSRF tokens). */
final class BrowserApprovalFormError extends RuntimeException
{
    public function __construct(public readonly string $reason)
    {
        parent::__construct('Browser approval rejected');
    }
}
