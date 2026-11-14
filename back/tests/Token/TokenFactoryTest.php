<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Token\TokenFactory;
use SymSvel\Module\Auth\Token\TokenPolicy;

final class TokenFactoryTest extends TestCase
{
    public function testContextsAreStrictlyLimited(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new TokenFactory())->issue('admin');
    }

    public function testTokensAreDistinctOpaqueSecretsAndHashed(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $pair = (new TokenFactory())->issue('bo', null, $now);

        self::assertSame('bo', $pair->context);
        self::assertMatchesRegularExpression('/^[a-f0-9]{32}$/D', $pair->familyId);
        self::assertNotSame($pair->access->raw, $pair->refresh->raw);
        self::assertSame(hash('sha256', $pair->access->raw), $pair->access->hash);
        self::assertSame(hash('sha256', $pair->refresh->raw), $pair->refresh->hash);
        self::assertSame(43, strlen($pair->access->raw));
        self::assertSame($now->getTimestamp() + 900, $pair->access->expiresAt->getTimestamp());
        self::assertSame($now->getTimestamp() + 2592000, $pair->refresh->expiresAt->getTimestamp());
    }

    public function testRotationRetainsFamilyButChangesSecrets(): void
    {
        $factory = new TokenFactory();
        $first = $factory->issue('app');
        $second = $factory->issue('app', $first->familyId);
        self::assertSame($first->familyId, $second->familyId);
        self::assertNotSame($first->refresh->hash, $second->refresh->hash);
    }

    public function testInvalidPolicyIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new TokenPolicy(900, 900);
    }
}
