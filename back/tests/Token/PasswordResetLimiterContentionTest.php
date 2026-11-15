<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Exception as DbalException;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Identity\PasswordResetLimiter;
use SymSvel\Module\Auth\Schema\PasswordResetLimitSchema;

/**
 * Tests two independent SQLite connections to a private temporary database.
 * No configured integration database or project tables are touched.
 */
final class PasswordResetLimiterContentionTest extends TestCase
{
    public function testConcurrentRequestCannotReserveAnAlreadyLockedWindow(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }

        $path = tempnam(sys_get_temp_dir(), 'symsvel-auth-limit-race-');
        self::assertNotFalse($path);
        $first = null;
        $second = null;

        try {
            $params = ['driver' => 'pdo_sqlite', 'path' => $path];
            $first = DriverManager::getConnection($params);
            $second = DriverManager::getConnection($params);

            $schema = new Schema();
            PasswordResetLimitSchema::apply($schema);
            foreach ($schema->toSql($first->getDatabasePlatform()) as $sql) {
                $first->executeStatement($sql);
            }

            $second->executeStatement('PRAGMA busy_timeout = 0');
            $secret = 'test-secret-at-least-16-characters';
            $limiterA = new PasswordResetLimiter($first, $secret);
            $limiterB = new PasswordResetLimiter($second, $secret);
            $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');

            $first->beginTransaction();
            try {
                self::assertTrue($limiterA->allow('bo', 'admin@example.test', '192.0.2.10', $now));

                // B must not be granted a slot while A has an uncommitted write.
                $blocked = false;
                try {
                    $blocked = !$limiterB->allow('bo', 'admin@example.test', '192.0.2.11', $now);
                } catch (DbalException) {
                    // SQLite's immediate lock failure must never be interpreted as success.
                    $blocked = true;
                }
                self::assertTrue($blocked, 'Concurrent requests must not both reserve the identifier window.');

                $first->commit();
            } finally {
                if ($first->isTransactionActive()) {
                    $first->rollBack();
                }
            }

            self::assertFalse($limiterB->allow('bo', 'admin@example.test', '192.0.2.11', $now));
            self::assertSame(2, (int) $first->fetchOne('SELECT COUNT(*) FROM symsvel_auth_reset_limits'));
        } finally {
            if ($second instanceof Connection) {
                $second->close();
            }
            if ($first instanceof Connection) {
                $first->close();
            }
            if (is_file($path)) {
                unlink($path);
            }
        }
    }
}
