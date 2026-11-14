<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Token\RefreshDecision;
use SymSvel\Module\Auth\Token\RefreshTokenGuard;
use SymSvel\Module\Auth\Token\RefreshTokenRecord;
use SymSvel\Module\Auth\Token\RefreshTokenState;
use SymSvel\Module\Auth\Token\TokenFactory;
use SymSvel\Module\Auth\Token\TokenPair;
use SymSvel\Module\Auth\Token\TokenRotation;
use SymSvel\Module\Auth\Token\TokenStore;
use SymSvel\Module\Auth\Token\TokenSubject;

final class TokenRotationTest extends TestCase
{
    public function testFreshTokenIsConsumedAndRotatedInOneTransaction(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $store = new InMemoryTokenStore();
        $raw = str_repeat('A', 43);
        $store->record = new RefreshTokenRecord(
            new TokenSubject('bo', 1),
            new RefreshTokenState('bo', str_repeat('a', 32), $now->modify('+1 hour')),
        );
        $rotation = new TokenRotation($store, new TokenFactory(), new RefreshTokenGuard(), new ActivePrincipal());

        $result = $rotation->rotate($raw, 'bo', $now);
        self::assertSame(RefreshDecision::Rotate, $result->decision);
        self::assertNotNull($result->pair);
        self::assertSame(str_repeat('a', 32), $result->pair->familyId);
        self::assertSame(['lock', 'consume', 'revoke_access', 'save'], $store->operations);
        self::assertSame(1, $store->transactions);
    }

    public function testReplayRevokesFamilyWithoutIssuingTokens(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $store = new InMemoryTokenStore();
        $store->record = new RefreshTokenRecord(
            new TokenSubject('bo', 1),
            new RefreshTokenState('bo', str_repeat('a', 32), $now->modify('+1 hour'), $now),
        );
        $result = (new TokenRotation($store, new TokenFactory(), new RefreshTokenGuard(), new ActivePrincipal()))->rotate(str_repeat('A', 43), 'bo', $now);
        self::assertSame(RefreshDecision::RevokeFamily, $result->decision);
        self::assertSame(['lock', 'revoke_family'], $store->operations);
    }

    public function testWrongContextNeverRevokesFamily(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $store = new InMemoryTokenStore();
        $store->record = new RefreshTokenRecord(
            new TokenSubject('bo', 1),
            new RefreshTokenState('bo', str_repeat('a', 32), $now->modify('+1 hour'), $now),
        );
        $result = (new TokenRotation($store, new TokenFactory(), new RefreshTokenGuard(), new ActivePrincipal()))->rotate(str_repeat('A', 43), 'app', $now);
        self::assertSame(RefreshDecision::Reject, $result->decision);
        self::assertSame(['lock'], $store->operations);
    }

    public function testLostConsumeRaceRevokesFamily(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $store = new InMemoryTokenStore();
        $store->consumeSucceeds = false;
        $store->record = new RefreshTokenRecord(
            new TokenSubject('bo', 1),
            new RefreshTokenState('bo', str_repeat('a', 32), $now->modify('+1 hour')),
        );
        $result = (new TokenRotation($store, new TokenFactory(), new RefreshTokenGuard(), new ActivePrincipal()))->rotate(str_repeat('A', 43), 'bo', $now);
        self::assertSame(RefreshDecision::RevokeFamily, $result->decision);
        self::assertSame(['lock', 'consume', 'revoke_family'], $store->operations);
    }

    public function testDisabledPrincipalRevokesFamilyWithoutIssuingTokens(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $store = new InMemoryTokenStore();
        $store->record = new RefreshTokenRecord(
            new TokenSubject('bo', 1),
            new RefreshTokenState('bo', str_repeat('a', 32), $now->modify('+1 hour')),
        );
        $principals = new ActivePrincipal();
        $principals->active = false;

        $result = (new TokenRotation($store, new TokenFactory(), new RefreshTokenGuard(), $principals))
            ->rotate(str_repeat('A', 43), 'bo', $now);

        self::assertSame(RefreshDecision::Reject, $result->decision);
        self::assertNull($result->pair);
        self::assertSame(['lock', 'revoke_family'], $store->operations);
        self::assertSame(1, $store->transactions);
    }

    public function testMalformedTokenDoesNotTouchStorage(): void
    {
        $store = new InMemoryTokenStore();
        $result = (new TokenRotation($store, new TokenFactory(), new RefreshTokenGuard(), new ActivePrincipal()))->rotate('bad', 'bo', new \DateTimeImmutable());
        self::assertSame(RefreshDecision::Reject, $result->decision);
        self::assertSame(0, $store->transactions);
    }
}

