<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Token\AccessTokenLookup;
use SymSvel\Module\Auth\Token\AccessTokenRecord;
use SymSvel\Module\Auth\Token\AccessTokenVerifier;
use SymSvel\Module\Auth\Token\TokenSubject;

final class AccessTokenVerifierTest extends TestCase
{
    public function testValidAccessIsAcceptedOnlyInItsOwnContext(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $subject = new TokenSubject('bo', 17);
        $lookup = new TestAccessLookup(new AccessTokenRecord($subject, $now->modify('+1 minute'), null));
        $verifier = new AccessTokenVerifier($lookup);

        self::assertSame($subject, $verifier->verify(str_repeat('A', 43), 'bo', $now));
        self::assertNull($verifier->verify(str_repeat('A', 43), 'app', $now));
        self::assertSame(2, $lookup->calls);
    }

    public function testExpiredRevokedAndMalformedTokensAreRejected(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $subject = new TokenSubject('bo', 17);
        $lookup = new TestAccessLookup(new AccessTokenRecord($subject, $now, null));
        $verifier = new AccessTokenVerifier($lookup);
        self::assertNull($verifier->verify(str_repeat('A', 43), 'bo', $now));

        $lookup->record = new AccessTokenRecord($subject, $now->modify('+1 minute'), $now);
        self::assertNull($verifier->verify(str_repeat('A', 43), 'bo', $now));
        self::assertNull($verifier->verify('bad', 'bo', $now));
        self::assertSame(2, $lookup->calls);
    }
}

final class TestAccessLookup implements AccessTokenLookup
{
    public int $calls = 0;

    public function __construct(public ?AccessTokenRecord $record)
    {
    }

    public function findAccessByHash(string $hash): ?AccessTokenRecord
    {
        ++$this->calls;

        return $this->record;
    }
}
