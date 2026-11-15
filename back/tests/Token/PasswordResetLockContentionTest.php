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
use SymSvel\Module\Auth\Schema\PasswordResetSchema;
use SymSvel\Module\Auth\Token\DbalPasswordResetStore;
use SymSvel\Module\Auth\Token\PasswordResetToken;
use SymSvel\Module\Auth\Token\TokenSubject;

/** Competing connections on the same reset token, using the existing DB matrix. */
final class PasswordResetLockContentionTest extends TestCase
{
    public function testSecondConnectionCannotConsumeLockedTokenAndReplayFails(): void
    {
        $url = getenv('SYMSVEL_AUTH_TEST_DATABASE_URL');
        $path = $url ? null : tempnam(sys_get_temp_dir(), 'symsvel-reset-race-');
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
            $manager = $first->createSchemaManager();
            self::assertFalse($manager->tablesExist(['symsvel_auth_password_reset_tokens']), 'Use an empty disposable Auth test database.');

            $schema = new Schema();
            PasswordResetSchema::apply($schema);
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

            $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
            $token = PasswordResetToken::issue('bo', $now);
            $storeA = new DbalPasswordResetStore($first);
            $storeB = new DbalPasswordResetStore($second);
            $storeA->save(new TokenSubject('bo', 71), $token, $now);

            $first->beginTransaction();
            try {
                self::assertSame(71, $storeA->consume('bo', $token->raw, $now));
                // A has consumed the token but has not committed yet.
                $blocked = false;
                try {
                    $storeB->consume('bo', $token->raw, $now);
                } catch (DbalException) {
                    $blocked = true;
                }
                self::assertTrue($blocked, 'The second connection must not consume an uncommitted reset token.');
                $first->commit();
            } finally {
                if ($first->isTransactionActive()) {
                    $first->rollBack();
                }
            }

            self::assertNull($storeB->consume('bo', $token->raw, $now));
            self::assertSame(1, (int) $first->fetchOne(
                'SELECT COUNT(*) FROM symsvel_auth_password_reset_tokens WHERE token_hash = ? AND used_at IS NOT NULL',
                [$token->hash],
            ));
        } finally {
            if ($second instanceof Connection) {
                $second->close();
            }
            if ($first instanceof Connection) {
                if ($created && $first->createSchemaManager()->tablesExist(['symsvel_auth_password_reset_tokens'])) {
                    $first->executeStatement('DROP TABLE symsvel_auth_password_reset_tokens');
                }
                $first->close();
            }
            if ($path !== null && is_file($path)) {
                unlink($path);
            }
        }
    }
}
