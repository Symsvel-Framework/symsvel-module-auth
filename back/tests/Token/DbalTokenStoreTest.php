<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Schema\AuthTokenSchema;
use SymSvel\Module\Auth\Token\DbalTokenStore;
use SymSvel\Module\Auth\Token\RefreshDecision;
use SymSvel\Module\Auth\Token\RefreshTokenGuard;
use SymSvel\Module\Auth\Token\TokenFactory;
use SymSvel\Module\Auth\Token\TokenRotation;
use SymSvel\Module\Auth\Token\TokenSubject;

final class DbalTokenStoreTest extends TestCase
{
    public function testSqliteRotationAndReplay(): void
    {
        $connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $schema = new \Doctrine\DBAL\Schema\Schema();
        AuthTokenSchema::apply($schema);
        foreach ($schema->toSql($connection->getDatabasePlatform()) as $sql) {
            $connection->executeStatement($sql);
        }
        $store = new DbalTokenStore($connection);
        $factory = new TokenFactory();
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $original = $factory->issue('bo', null, $now);
        $store->transaction(fn () => $store->savePair(new TokenSubject('bo', 1), $original, $now));

        $rotation = new TokenRotation($store, $factory, new RefreshTokenGuard());
        $result = $rotation->rotate($original->refresh->raw, 'bo', $now->modify('+1 second'));
        self::assertSame(RefreshDecision::Rotate, $result->decision);
        self::assertNotNull($result->pair);
        self::assertSame(1, (int) $connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE used_at IS NOT NULL'));

        $replay = $rotation->rotate($original->refresh->raw, 'bo', $now->modify('+2 seconds'));
        self::assertSame(RefreshDecision::RevokeFamily, $replay->decision);
        self::assertSame(2, (int) $connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE revoked_at IS NOT NULL'));
        self::assertSame(2, (int) $connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_access_tokens WHERE revoked_at IS NOT NULL'));
    }
}
