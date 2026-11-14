<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Token\RefreshTokenRecord;
use SymSvel\Module\Auth\Token\RefreshTokenState;
use SymSvel\Module\Auth\Token\TokenLogout;
use SymSvel\Module\Auth\Token\TokenSubject;

final class TokenLogoutTest extends TestCase
{
    public function testLogoutRevokesOnlyMatchingContextFamily(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $store = new InMemoryTokenStore();
        $store->record = new RefreshTokenRecord(
            new TokenSubject('bo', 7),
            new RefreshTokenState('bo', str_repeat('a', 32), $now->modify('+1 hour')),
        );
        $logout = new TokenLogout($store);

        self::assertFalse($logout->logout(str_repeat('A', 43), 'app', $now));
        self::assertSame(['lock'], $store->operations);
        $store->operations = [];

        self::assertTrue($logout->logout(str_repeat('A', 43), 'bo', $now));
        self::assertSame(['lock', 'revoke_family'], $store->operations);
    }

    public function testMalformedSecretDoesNotAccessStorage(): void
    {
        $store = new InMemoryTokenStore();
        self::assertFalse((new TokenLogout($store))->logout('bad', 'bo', new \DateTimeImmutable()));
        self::assertSame(0, $store->transactions);
    }
}
