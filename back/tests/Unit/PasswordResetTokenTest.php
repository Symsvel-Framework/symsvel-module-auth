<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Token\PasswordResetToken;

final class PasswordResetTokenTest extends TestCase
{
    public function testIssuesIndependentOpaqueSecretsForEachContext(): void
    {
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        $bo = PasswordResetToken::issue('bo', $now);
        $app = PasswordResetToken::issue('app', $now);
        self::assertSame('bo', $bo->context);
        self::assertSame('app', $app->context);
        self::assertNotSame($bo->raw, $app->raw);
        self::assertSame(hash('sha256', $bo->raw), $bo->hash);
        self::assertSame($bo->hash, PasswordResetToken::fingerprint($bo->raw));
        self::assertEquals($now->modify('+1800 seconds'), $bo->expiresAt);
    }

    public function testRejectsMalformedTokensAndContexts(): void
    {
        self::assertNull(PasswordResetToken::fingerprint('not-a-token'));
        $this->expectException(\InvalidArgumentException::class);
        PasswordResetToken::issue('unknown', new \DateTimeImmutable());
    }

    public function testRejectsInvalidLifetime(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        PasswordResetToken::issue('bo', new \DateTimeImmutable(), 0);
    }
}
