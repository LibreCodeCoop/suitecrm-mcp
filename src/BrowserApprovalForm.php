<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp;

final class BrowserApprovalForm
{
    /**
     * A model cannot satisfy this form: it requires a fresh HttpOnly cookie,
     * the corresponding CSRF secret in the HTML, and a same-origin browser POST.
     * Origin / Fetch Metadata are additional checks when transmitted;
     * an exact one-time CSRF secret and HttpOnly cookie remain mandatory.
     */
    public static function validate(
        string $expectedOrigin,
        ?string $origin,
        ?string $fetchSite,
        mixed $ticket,
        mixed $csrf
    ): array {
        if ($origin !== null && !hash_equals($expectedOrigin, $origin)) {
            throw new BrowserApprovalFormError('origin_mismatch');
        }
        if ($fetchSite !== null && $fetchSite !== 'same-origin') {
            throw new BrowserApprovalFormError('cross_site_request');
        }
        if (!is_string($ticket) || strlen($ticket) !== 43 ||
            preg_match('/^[A-Za-z0-9_-]{43}$/D', $ticket) !== 1) {
            throw new BrowserApprovalFormError('session_cookie_missing');
        }
        if (!is_string($csrf) || strlen($csrf) !== 43 ||
            preg_match('/^[A-Za-z0-9_-]{43}$/D', $csrf) !== 1) {
            throw new BrowserApprovalFormError('csrf_missing');
        }
        return [$ticket, $csrf];
    }
}
