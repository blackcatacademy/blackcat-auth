<?php
declare(strict_types=1);

namespace BlackCat\Auth\Tests\Registration;

use BlackCat\Auth\Registration\EmailVerificationToken;
use PHPUnit\Framework\TestCase;

final class EmailVerificationTokenTest extends TestCase
{
    public function testIssueAndParse(): void
    {
        $issued = EmailVerificationToken::issue();
        self::assertMatchesRegularExpression('~^[A-Za-z0-9_-]{12}$~', $issued->selector);
        self::assertNotEmpty($issued->validator);

        $token = $issued->token();
        $parsed = EmailVerificationToken::parse($token);
        self::assertNotNull($parsed);
        self::assertSame($issued->selector, $parsed->selector);
        self::assertSame($issued->validator, $parsed->validator);

        $validatorHash = $parsed->validatorHashBinary();
        self::assertIsString($validatorHash);
        self::assertSame(32, strlen((string)$validatorHash));

        $tokenHash = $parsed->tokenHashHex();
        self::assertSame(64, strlen($tokenHash));
        self::assertMatchesRegularExpression('~^[a-f0-9]{64}$~', $tokenHash);
    }

    public function testParseRejectsInvalid(): void
    {
        self::assertNull(EmailVerificationToken::parse(''));
        self::assertNull(EmailVerificationToken::parse('no-dot'));
        self::assertNull(EmailVerificationToken::parse('short.short'));
        self::assertNull(EmailVerificationToken::parse(str_repeat('a', 12) . '.not*base64'));
    }
}

