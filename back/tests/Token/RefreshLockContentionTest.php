<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Tools\DsnParser;
use Doctrine\DBAL\Exception as DbalException;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\DBAL\Platforms\SQLitePlatform;
use Doctrine\DBAL\Platforms\PostgreSQLPlatform;
use Doctrine\DBAL\Platforms\AbstractMySQLPlatform;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Schema\AuthTokenSchema;
use SymSvel\Module\Auth\Token\DbalTokenStore;
use SymSvel\Module\Auth\Token\TokenFactory;
use SymSvel\Module\Auth\Token\TokenSubject;
use SymSvel\Module\Auth\Token\TokenRotation;
use SymSvel\Module\Auth\Token\RefreshTokenGuard;
use SymSvel\Module\Auth\Token\RefreshDecision;
use SymSvel\Module\Auth\Identity\PrincipalStatus;

/**
 * Two real DBAL connections compete for the same refresh row.
 * With SYMSVEL_AUTH_TEST_DATABASE_URL, use an EMPTY disposable database.
 */
final class RefreshLockContentionTest extends TestCase
{
    public function testConcurrentRotationsHaveOneWinnerAndRevokeOnReplay(): void
    {
        if (!function_exists('pcntl_fork') || !function_exists('pcntl_waitpid')) {
            self::markTestSkipped('Process concurrency requires pcntl.');
        }

        $url = getenv('SYMSVEL_AUTH_TEST_DATABASE_URL');
        $path = $url ? null : tempnam(sys_get_temp_dir(), 'symsvel-auth-fork-');
        self::assertTrue($url !== false || $path !== false);
        $params = $url
            ? (new DsnParser(['postgresql' => 'pdo_pgsql', 'mysql' => 'pdo_mysql', 'mariadb' => 'pdo_mysql']))->parse($url)
            : ['driver' => 'pdo_sqlite', 'path' => $path];
        $connection = DriverManager::getConnection($params);
        $tables = ['symsvel_auth_access_tokens', 'symsvel_auth_refresh_tokens'];
        $created = [];
        $childPid = null;
        $sockets = null;

        try {
            $manager = $connection->createSchemaManager();
            foreach ($tables as $table) {
                self::assertFalse($manager->tablesExist([$table]), 'Use a disposable empty Auth database.');
            }
            $schema = new Schema();
            AuthTokenSchema::apply($schema);
            foreach ($schema->toSql($connection->getDatabasePlatform()) as $sql) {
                $connection->executeStatement($sql);
                foreach ($tables as $table) {
                    if (!in_array($table, $created, true) && $manager->tablesExist([$table])) {
                        $created[] = $table;
                    }
                }
            }
            $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
            $pair = (new TokenFactory())->issue('bo', null, $now);
            $store = new DbalTokenStore($connection);
            $store->transaction(fn () => $store->savePair(new TokenSubject('bo', 1), $pair, $now));
            $connection->close(); // Never share a DB connection across fork.

            $sockets = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, 0);
            self::assertIsArray($sockets);
            $childPid = pcntl_fork();
            self::assertNotSame(-1, $childPid);
            if ($childPid === 0) {
                fclose($sockets[0]);
                try {
                    $signal = fgets($sockets[1]);
                    if ($signal !== "go\n") {
                        exit(3);
                    }
                    $childConnection = DriverManager::getConnection($params);
                    if ($childConnection->getDatabasePlatform() instanceof SQLitePlatform) {
                        $childConnection->executeStatement('PRAGMA busy_timeout = 5000');
                    }
                    $childStore = new DbalTokenStore($childConnection);
                    $result = (new TokenRotation($childStore, new TokenFactory(), new RefreshTokenGuard(), new ActivePrincipal()))
                        ->rotate($pair->refresh->raw, 'bo', $now->modify('+2 seconds'));
                    $childConnection->close();
                    exit($result->decision === RefreshDecision::RevokeFamily ? 0 : 4);
                } catch (\Throwable $e) {
                    fwrite(STDERR, 'Concurrent child: '.$e->getMessage()."\n");
                    exit(5);
                }
            }

            fclose($sockets[1]);
            $parentConnection = DriverManager::getConnection($params);
            $parentStore = new DbalTokenStore($parentConnection);
            $principal = new class($sockets[0]) implements PrincipalStatus {
                public function __construct(private $socket) {}
                public function isActive(TokenSubject $subject): bool
                {
                    fwrite($this->socket, "go\n");
                    fflush($this->socket);
                    usleep(300000); // Child enters rotation while parent holds the row lock.
                    return true;
                }
            };
            $result = (new TokenRotation($parentStore, new TokenFactory(), new RefreshTokenGuard(), $principal))
                ->rotate($pair->refresh->raw, 'bo', $now->modify('+1 second'));
            self::assertSame(RefreshDecision::Rotate, $result->decision);
            $status = 0;
            pcntl_waitpid($childPid, $status);
            $childPid = null;
            self::assertTrue(pcntl_wifexited($status));
            self::assertSame(0, pcntl_wexitstatus($status), 'Concurrent replay must revoke the family.');
            self::assertSame(2, (int) $parentConnection->fetchOne(
                'SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE family_id = ? AND revoked_at IS NOT NULL',
                [$pair->familyId],
            ));
            $parentConnection->close();
        } finally {
            if ($sockets !== null) {
                foreach ($sockets as $socket) {
                    if (is_resource($socket)) {
                        fclose($socket);
                    }
                }
            }
            if ($childPid !== null && $childPid > 0) {
                pcntl_waitpid($childPid, $status);
            }
            $cleanup = DriverManager::getConnection($params);
            foreach (array_reverse($created) as $table) {
                if ($cleanup->createSchemaManager()->tablesExist([$table])) {
                    $cleanup->executeStatement('DROP TABLE '.$table);
                }
            }
            $cleanup->close();
            if ($path !== null && is_file($path)) {
                unlink($path);
            }
        }
    }

    public function testSecondConnectionFailsClosedWhileFirstHoldsRefreshLock(): void
    {
        $url = getenv('SYMSVEL_AUTH_TEST_DATABASE_URL');
        $path = $url ? null : tempnam(sys_get_temp_dir(), 'symsvel-auth-race-');
        if (!$url) {
            self::assertNotFalse($path);
        }

        $params = $url
            ? (new DsnParser(['postgresql' => 'pdo_pgsql', 'mysql' => 'pdo_mysql', 'mariadb' => 'pdo_mysql']))->parse($url)
            : ['driver' => 'pdo_sqlite', 'path' => $path];
        $first = null;
        $second = null;
        $created = [];

        try {
            $first = DriverManager::getConnection($params);
            $second = DriverManager::getConnection($params);
            $platform = $first->getDatabasePlatform();
            $manager = $first->createSchemaManager();
            $tables = ['symsvel_auth_access_tokens', 'symsvel_auth_refresh_tokens'];
            foreach ($tables as $table) {
                self::assertFalse($manager->tablesExist([$table]), 'Use an empty disposable Auth test database.');
            }

            $schema = new Schema();
            AuthTokenSchema::apply($schema);
            foreach ($schema->toSql($first->getDatabasePlatform()) as $sql) {
                $first->executeStatement($sql);
                foreach ($tables as $table) {
                    if (!in_array($table, $created, true) && $manager->tablesExist([$table])) {
                        $created[] = $table;
                    }
                }
            }

            $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
            $pair = (new TokenFactory())->issue('bo', null, $now);
            $storeA = new DbalTokenStore($first);
            $storeB = new DbalTokenStore($second);
            $storeA->transaction(fn () => $storeA->savePair(new TokenSubject('bo', 1), $pair, $now));

            // Bound waiting so a broken lock never hangs a CI runner.
            if ($platform instanceof SQLitePlatform) {
                $second->executeStatement('PRAGMA busy_timeout = 0');
            } elseif ($platform instanceof PostgreSQLPlatform) {
                $second->executeStatement("SET lock_timeout = '200ms'");
            } elseif ($platform instanceof AbstractMySQLPlatform) {
                $second->executeStatement('SET SESSION innodb_lock_wait_timeout = 1');
            } else {
                self::markTestSkipped('Lock timeout not configured for '.get_debug_type($platform));
            }

            $first->beginTransaction();
            try {
                self::assertNotNull($storeA->lockRefresh($pair->refresh->hash));
                $second->beginTransaction();
                try {
                    $blocked = false;
                    try {
                        $storeB->lockRefresh($pair->refresh->hash);
                    } catch (DbalException) {
                        $blocked = true;
                    }
                    self::assertTrue($blocked, 'The second connection must not acquire the locked refresh.');
                } finally {
                    if ($second->isTransactionActive()) {
                        $second->rollBack();
                    }
                }
            } finally {
                if ($first->isTransactionActive()) {
                    $first->rollBack();
                }
            }

            self::assertNotNull($storeB->transaction(fn () => $storeB->lockRefresh($pair->refresh->hash)));

            // Once the first contender commits consumption, the second
            // connection must observe the used state and cannot consume again.
            self::assertTrue($storeA->transaction(fn () => $storeA->consumeRefresh(
                $pair->refresh->hash,
                $now->modify('+1 second'),
            )));
            $observed = $storeB->transaction(fn () => $storeB->lockRefresh($pair->refresh->hash));
            self::assertNotNull($observed);
            self::assertNotNull($observed->state->usedAt);
            self::assertFalse($storeB->transaction(fn () => $storeB->consumeRefresh(
                $pair->refresh->hash,
                $now->modify('+2 seconds'),
            )));
        } finally {
            if ($second !== null) {
                $second->close();
            }
            if ($first !== null) {
                foreach (array_reverse($created) as $table) {
                    if ($first->createSchemaManager()->tablesExist([$table])) {
                        $first->executeStatement('DROP TABLE '.$table);
                    }
                }
                $first->close();
            }
            if ($path !== null && is_file($path)) {
                unlink($path);
            }
        }
    }
}
