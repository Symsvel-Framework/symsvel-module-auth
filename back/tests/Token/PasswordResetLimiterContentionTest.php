<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Exception as DbalException;
use Doctrine\DBAL\Platforms\AbstractMySQLPlatform;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\DBAL\Tools\DsnParser;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use SymSvel\Module\Auth\Identity\PasswordResetLimiter;
use SymSvel\Module\Auth\Schema\PasswordResetLimitSchema;

/**
 * Contention between two DBAL connections using the existing Auth database
 * matrix. SQLite uses a temporary file; external databases must be disposable.
 */
final class PasswordResetLimiterContentionTest extends TestCase
{
    /** @return iterable<string, array{string, string, string, string}> */
    public static function competingRequests(): iterable
    {
        yield 'same identifier, different IPs' => [
            'admin@example.test', '192.0.2.10', 'admin@example.test', '192.0.2.11',
        ];
        yield 'different identifiers, same IP' => [
            'first@example.test', '192.0.2.10', 'second@example.test', '192.0.2.10',
        ];
    }

    #[DataProvider('competingRequests')]
    public function testConcurrentRequestCannotReserveAnAlreadyLockedWindow(
        string $firstIdentifier,
        string $firstIp,
        string $secondIdentifier,
        string $secondIp,
    ): void
    {
        $url = getenv('SYMSVEL_AUTH_TEST_DATABASE_URL');
        if (!$url && !extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required without an external test database.');
        }

        $path = $url ? null : tempnam(sys_get_temp_dir(), 'symsvel-auth-limit-race-');
        if (!$url) {
            self::assertNotFalse($path);
        }
        $params = $url
            ? (new DsnParser(['postgresql' => 'pdo_pgsql', 'mysql' => 'pdo_mysql', 'mariadb' => 'pdo_mysql']))->parse($url)
            : ['driver' => 'pdo_sqlite', 'path' => $path];

        $first = null;
        $second = null;
        $created = false;
        try {
            $first = DriverManager::getConnection($params);
            $second = DriverManager::getConnection($params);
            self::assertFalse(
                $first->createSchemaManager()->tablesExist(['symsvel_auth_reset_limits']),
                'Use an empty disposable Auth test database.',
            );

            $schema = new Schema();
            PasswordResetLimitSchema::apply($schema);
            foreach ($schema->toSql($first->getDatabasePlatform()) as $sql) {
                $first->executeStatement($sql);
            }
            $created = true;

            $platform = $first->getDatabasePlatform();
            if ($platform instanceof SQLitePlatform) {
                $second->executeStatement('PRAGMA busy_timeout = 0');
            } elseif ($platform instanceof PostgreSQLPlatform) {
                $second->executeStatement("SET lock_timeout = '200ms'");
            } elseif ($platform instanceof AbstractMySQLPlatform) {
                $second->executeStatement('SET SESSION innodb_lock_wait_timeout = 1');
            } else {
                self::markTestSkipped('Unsupported lock timeout for '.get_debug_type($platform));
            }

            $secret = 'test-secret-at-least-16-characters';
            $limiterA = new PasswordResetLimiter($first, $secret);
            $limiterB = new PasswordResetLimiter($second, $secret);
            $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');

            $first->beginTransaction();
            try {
                self::assertTrue($limiterA->allow('bo', $firstIdentifier, $firstIp, $now));

                // B competes for either the same identifier or the same IP
                // while A holds its uncommitted unique key.
                $blocked = false;
                try {
                    $blocked = !$limiterB->allow('bo', $secondIdentifier, $secondIp, $now);
                } catch (DbalException) {
                    // A database lock timeout must never grant a reservation.
                    $blocked = true;
                }
                self::assertTrue($blocked, 'Concurrent requests must not both reserve a shared rate limit window.');
                $first->commit();
            } finally {
                if ($first->isTransactionActive()) {
                    $first->rollBack();
                }
            }

            self::assertFalse($limiterB->allow('bo', $secondIdentifier, $secondIp, $now));
            self::assertSame(2, (int) $first->fetchOne('SELECT COUNT(*) FROM symsvel_auth_reset_limits'));
        } finally {
            if ($second instanceof Connection) {
                $second->close();
            }
            if ($first instanceof Connection) {
                if ($created && $first->createSchemaManager()->tablesExist(['symsvel_auth_reset_limits'])) {
                    $first->executeStatement('DROP TABLE symsvel_auth_reset_limits');
                }
                $first->close();
            }
            if ($path !== null && is_file($path)) {
                unlink($path);
            }
        }
    }
}
