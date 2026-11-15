<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Identity\PasswordResetLimiter;
use SymSvel\Module\Auth\Schema\PasswordResetLimitSchema;

final class PasswordResetLimiterTest extends TestCase
{
    public function testSameIdentifierIsDeniedWithinWindowAcrossIpAddresses(): void
    {
        [$limiter, $db] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        self::assertTrue($limiter->allow('bo', ' ADMIN@example.test ', '192.0.2.10', $now));
        self::assertFalse($limiter->allow('bo', 'admin@example.test', '192.0.2.11', $now));
        self::assertSame(2, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_reset_limits'));
        self::assertTrue($limiter->allow('bo', 'admin@example.test', '192.0.2.10', $now->modify('+5 minutes')));
    }

    public function testSameIpIsDeniedEvenForDifferentOrUnknownAccounts(): void
    {
        [$limiter, $db] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        self::assertTrue($limiter->allow('bo', 'missing-one', '192.0.2.10', $now));
        self::assertFalse($limiter->allow('bo', 'missing-two', '192.0.2.10', $now));
        self::assertSame(2, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_reset_limits'));
        self::assertTrue($limiter->allow('bo', 'missing-two', '192.0.2.10', $now->modify('+10 seconds')));
    }

    public function testContextsAndInvalidIpAreIsolatedAndNoRawIdentifierIsStored(): void
    {
        [$limiter, $db] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        self::assertFalse($limiter->allow('bo', 'known', 'invalid-ip', $now));
        self::assertSame(0, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_reset_limits'));
        self::assertTrue($limiter->allow('bo', 'known@example.test', '192.0.2.10', $now));
        self::assertTrue($limiter->allow('app', 'known@example.test', '192.0.2.10', $now));
        $keys = $db->fetchFirstColumn('SELECT key_hash FROM symsvel_auth_reset_limits');
        self::assertCount(4, $keys);
        foreach ($keys as $hash) {
            self::assertMatchesRegularExpression('/^[a-f0-9]{64}$/D', (string) $hash);
            self::assertNotSame(hash('sha256', 'known@example.test'), $hash);
        }
    }

    private function fixture(): array
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $db = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $schema = new Schema();
        PasswordResetLimitSchema::apply($schema);
        foreach ($schema->toSql($db->getDatabasePlatform()) as $sql) {
            $db->executeStatement($sql);
        }

        return [new PasswordResetLimiter($db, 'test-secret-at-least-16-characters'), $db];
    }
}
