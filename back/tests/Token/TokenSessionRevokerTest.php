<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Token\TokenSessionRevoker;
use SymSvel\Module\Auth\Token\TokenSubject;

final class TokenSessionRevokerTest extends TestCase
{
    public function testRevokesSubjectWithinTransaction(): void
    {
        $store = new InMemoryTokenStore();
        (new TokenSessionRevoker($store))->revokeAll(
            new TokenSubject('bo', 12),
            new \DateTimeImmutable('2026-11-14T10:00:00+00:00'),
        );

        self::assertSame(1, $store->transactions);
        self::assertSame(['revoke_subject'], $store->operations);
    }
}
