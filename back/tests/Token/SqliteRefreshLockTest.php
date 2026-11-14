<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Schema\AuthTokenSchema;
use SymSvel\Module\Auth\Token\DbalTokenStore;
use SymSvel\Module\Auth\Token\TokenFactory;
use SymSvel\Module\Auth\Token\TokenSubject;

/**
 * Uses two distinct connections to the same temporary SQLite file.
 * Never touches SYMSVEL_AUTH_TEST_DATABASE_URL.
 */
final class SqliteRefreshLockTest extends TestCase
{
    public function testSecondConnectionCannotReadRefreshForRotationBeforeFirstTransactionEnds(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'symsvel-auth-lock-');
        self::assertNotFalse($path);
        $first = null;
        $second = null;

        try {
            $params = ['driver' => 'pdo_sqlite', 'path' => $path];
            $first = DriverManager::getConnection($params);
            $second = DriverManager::getConnection($params);
            $schema = new Schema();
            AuthTokenSchema::apply($schema);
            foreach ($schema->toSql($first->getDatabasePlatform()) as $sql) {
                $first->executeStatement($sql);
            }

            $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
            $pair = (new TokenFactory())->issue('bo', null, $now);
            $storeA = new DbalTokenStore($first);
            $storeB = new DbalTokenStore($second);
            $storeA->transaction(fn () => $storeA->savePair(new TokenSubject('bo', 1), $pair, $now));
            $second->executeStatement('PRAGMA busy_timeout = 0');

            $first->beginTransaction();
            try {
                self::assertNotNull($storeA->lockRefresh($pair->refresh->hash));

                $second->beginTransaction();
                try {
                    $blocked = false;
                    try {
                        $storeB->lockRefresh($pair->refresh->hash);
                    } catch (\Doctrine\DBAL\Exception $exception) {
                        $blocked = true;
                    }
                    self::assertTrue($blocked, 'Concurrent SQLite refresh reader must fail closed while writer lock is held.');
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
        } finally {
            if ($second !== null) {
                $second->close();
            }
            if ($first !== null) {
                $first->close();
            }
            unlink($path);
        }
    }
}
