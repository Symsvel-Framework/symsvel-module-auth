<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Token\TokenFactory;
use SymSvel\Module\Auth\Token\TokenIssuer;
use SymSvel\Module\Auth\Token\TokenSubject;

final class TokenIssuerTest extends TestCase
{
    public function testIssuesAndPersistsOneFamilyWithinTransaction(): void
    {
        $store = new InMemoryTokenStore();
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $pair = (new TokenIssuer($store, new TokenFactory()))->issue(new TokenSubject('bo', 17), $now);

        self::assertSame('bo', $pair->context);
        self::assertSame(1, $store->transactions);
        self::assertSame(['save'], $store->operations);
        self::assertSame(43, strlen($pair->access->raw));
        self::assertSame(43, strlen($pair->refresh->raw));
        self::assertNotSame($pair->access->hash, $pair->refresh->hash);
    }

    public function testAppSubjectIssuesAppTokens(): void
    {
        $pair = (new TokenIssuer(new InMemoryTokenStore(), new TokenFactory()))
            ->issue(new TokenSubject('app', 9), new \DateTimeImmutable('2026-11-14T10:00:00+00:00'));

        self::assertSame('app', $pair->context);
    }
}
