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

    public function testRunsAccountMutationBeforeRevocationInOneTransaction(): void
    {
        $store = new InMemoryTokenStore();
        $revoker = new TokenSessionRevoker($store);
        $result = $revoker->revokeWith(
            new TokenSubject('app', 7),
            new \DateTimeImmutable('2026-11-16T12:00:00+00:00'),
            static function () use ($store): string {
                $store->operations[] = 'update_account';
                return 'updated';
            },
        );

        self::assertSame('updated', $result);
        self::assertSame(1, $store->transactions);
        self::assertSame(['update_account', 'revoke_subject'], $store->operations);
    }

    public function testAbortedAccountMutationNeverRevokesSessions(): void
    {
        $store = new InMemoryTokenStore();
        $revoker = new TokenSessionRevoker($store);
        try {
            $revoker->revokeWith(
                new TokenSubject('bo', 7),
                new \DateTimeImmutable('2026-11-16T12:00:00+00:00'),
                static function (): void { throw new \RuntimeException('Account update failed'); },
            );
            self::fail('Failed mutation must propagate');
        } catch (\RuntimeException $exception) {
            self::assertSame('Account update failed', $exception->getMessage());
        }
        self::assertSame(1, $store->transactions);
        self::assertSame([], $store->operations);
    }
}
