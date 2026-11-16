<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Token\AdminInvitationToken;

final class AdminInvitationTokenTest extends TestCase
{
    public function testIssuesOpaqueIndependentInvitationTokens(): void
    {
        $now = new \DateTimeImmutable('2026-11-16T12:00:00+00:00');
        $first = AdminInvitationToken::issue($now);
        $second = AdminInvitationToken::issue($now);

        self::assertNotSame($first->raw, $second->raw);
        self::assertSame(hash('sha256', $first->raw), $first->hash);
        self::assertSame($first->hash, AdminInvitationToken::fingerprint($first->raw));
        self::assertSame($now->modify('+3600 seconds'), $first->expiresAt);
    }

    public function testRejectsMalformedInput(): void
    {
        self::assertNull(AdminInvitationToken::fingerprint('bad-token'));

        $this->expectException(\InvalidArgumentException::class);
        AdminInvitationToken::issue(new \DateTimeImmutable(), 0);
    }

    public function testRejectsMismatchedFingerprint(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new AdminInvitationToken(str_repeat('A', 43), str_repeat('0', 64), new \DateTimeImmutable());
    }
}
