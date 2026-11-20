<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Identity\AuthenticatedTokenResolver;
use SymSvel\Module\Auth\Identity\PrincipalStatus;
use SymSvel\Module\Auth\Token\AccessTokenLookup;
use SymSvel\Module\Auth\Token\AccessTokenRecord;
use SymSvel\Module\Auth\Token\AccessTokenVerifier;
use SymSvel\Module\Auth\Token\TokenSubject;

final class AuthenticatedTokenResolverTest extends TestCase
{
    public function testActiveAccountIsRequiredEvenWithValidToken(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $subject = new TokenSubject('bo', 17);
        $lookup = new class($subject, $now) implements AccessTokenLookup {
            public function __construct(private TokenSubject $subject, private \DateTimeImmutable $now) {}
            public function findAccessByHash(string $hash): ?AccessTokenRecord
            {
                return new AccessTokenRecord($this->subject, $this->now->modify('+1 hour'), null);
            }
        };
        $status = new class implements PrincipalStatus {
            public bool $active = true;
            public int $calls = 0;
            public function isActive(TokenSubject $subject): bool
            {
                ++$this->calls;
                return $this->active;
            }
        };
        $resolver = new AuthenticatedTokenResolver(new AccessTokenVerifier($lookup), $status);

        self::assertSame($subject, $resolver->resolve(str_repeat('A', 43), 'bo', $now));
        $status->active = false;
        self::assertNull($resolver->resolve(str_repeat('A', 43), 'bo', $now));
        self::assertNull($resolver->resolve('malformed', 'bo', $now));
        self::assertNull($resolver->resolve(str_repeat('A', 43), 'app', $now));
        self::assertSame(2, $status->calls, 'Invalid tokens must not trigger principal lookups.');
    }
}
