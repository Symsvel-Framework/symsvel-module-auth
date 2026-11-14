<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Identity\PasswordLogin;
use SymSvel\Module\Auth\Identity\PasswordPrincipal;
use SymSvel\Module\Auth\Token\TokenFactory;
use SymSvel\Module\Auth\Token\TokenIssuer;
use SymSvel\Module\Auth\Token\TokenSubject;

final class PasswordLoginTest extends TestCase
{
    public function testOnlyAuthenticatedMatchingContextIssuesTokens(): void
    {
        $principal = new class implements PasswordPrincipal {
            public int $calls = 0;
            public ?TokenSubject $subject = null;

            public function authenticate(string $context, string $identifier, string $password): ?TokenSubject
            {
                ++$this->calls;
                return $this->subject;
            }
        };
        $store = new InMemoryTokenStore();
        $login = new PasswordLogin($principal, new TokenIssuer($store, new TokenFactory()));
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');

        self::assertNull($login->login('invalid', 'a@example.com', 'secret', $now));
        self::assertSame(0, $principal->calls);
        self::assertSame(0, $store->transactions);

        self::assertNull($login->login('bo', 'a@example.com', 'wrong', $now));
        self::assertSame(0, $store->transactions);

        $principal->subject = new TokenSubject('app', 5);
        self::assertNull($login->login('bo', 'a@example.com', 'secret', $now));
        self::assertSame(0, $store->transactions);

        $principal->subject = new TokenSubject('bo', 5);
        $pair = $login->login('bo', 'a@example.com', 'secret', $now);
        self::assertNotNull($pair);
        self::assertSame('bo', $pair->context);
        self::assertSame(1, $store->transactions);
        self::assertSame(['save'], $store->operations);
    }
}
