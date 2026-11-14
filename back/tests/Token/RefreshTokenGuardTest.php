<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Token\RefreshDecision;
use SymSvel\Module\Auth\Token\RefreshTokenGuard;
use SymSvel\Module\Auth\Token\RefreshTokenState;

final class RefreshTokenGuardTest extends TestCase
{
    public function testFreshTokenMayRotateOnlyInItsContext(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $state = new RefreshTokenState('bo', 'family', $now->modify('+1 hour'));
        $guard = new RefreshTokenGuard();
        self::assertSame(RefreshDecision::Rotate, $guard->decide($state, 'bo', $now));
        self::assertSame(RefreshDecision::Reject, $guard->decide($state, 'app', $now));
    }

    public function testReplayedTokenRequiresFamilyRevocation(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $state = new RefreshTokenState('app', 'family', $now->modify('+1 hour'), $now->modify('-1 minute'));
        self::assertSame(RefreshDecision::RevokeFamily, (new RefreshTokenGuard())->decide($state, 'app', $now));
    }

    public function testExpiredAndRevokedTokensAreRejected(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $guard = new RefreshTokenGuard();
        self::assertSame(RefreshDecision::Reject, $guard->decide(new RefreshTokenState('bo', 'family', $now), 'bo', $now));
        self::assertSame(RefreshDecision::Reject, $guard->decide(new RefreshTokenState('bo', 'family', $now->modify('+1 hour'), null, $now), 'bo', $now));
    }
}
