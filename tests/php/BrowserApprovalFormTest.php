<?php

// SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
declare(strict_types=1);

namespace SuiteCrmMcp\Tests;

use PHPUnit\Framework\TestCase;
use SuiteCrmMcp\BrowserApprovalForm;
use SuiteCrmMcp\BrowserApprovalFormError;

final class BrowserApprovalFormTest extends TestCase
{
    private const ORIGIN = 'https://crm.example.com';
    private const TOKEN = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq';

    public function testAcceptsExplicitSameOriginPost(): void
    {
        self::assertSame([self::TOKEN, self::TOKEN], BrowserApprovalForm::validate(
            self::ORIGIN,
            self::ORIGIN,
            'same-origin',
            self::TOKEN,
            self::TOKEN
        ));
    }

    public function testAllowsBrowserPrivacySettingsOmittingOriginWithFetchMetadata(): void
    {
        self::assertSame([self::TOKEN, self::TOKEN], BrowserApprovalForm::validate(
            self::ORIGIN,
            null,
            'same-origin',
            self::TOKEN,
            self::TOKEN
        ));
    }

    public function testRejectsExplicitCrossOriginEvenWithForgedFetchMetadata(): void
    {
        $this->expectException(BrowserApprovalFormError::class);
        $this->expectExceptionMessage('Browser approval rejected');
        BrowserApprovalForm::validate(
            self::ORIGIN,
            'https://attacker.example',
            'same-origin',
            self::TOKEN,
            self::TOKEN
        );
    }

    public function testRejectsCrossSiteFetchMetadataEvenWithExpectedOrigin(): void
    {
        $this->expectException(BrowserApprovalFormError::class);
        BrowserApprovalForm::validate(
            self::ORIGIN,
            self::ORIGIN,
            'cross-site',
            self::TOKEN,
            self::TOKEN
        );
    }

    public function testDoesNotRequireOptionalBrowserMetadataWhenCsrfAndCookieAreValid(): void
    {
        self::assertSame([self::TOKEN, self::TOKEN], BrowserApprovalForm::validate(
            self::ORIGIN,
            null,
            null,
            self::TOKEN,
            self::TOKEN
        ));
    }

    public function testRejectsMissingBrowserCookie(): void
    {
        $this->expectException(BrowserApprovalFormError::class);
        BrowserApprovalForm::validate(
            self::ORIGIN,
            self::ORIGIN,
            'same-origin',
            null,
            self::TOKEN
        );
    }

    public function testRejectsMissingFormCsrf(): void
    {
        $this->expectException(BrowserApprovalFormError::class);
        BrowserApprovalForm::validate(
            self::ORIGIN,
            self::ORIGIN,
            'same-origin',
            self::TOKEN,
            null
        );
    }
}
