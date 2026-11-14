<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Schema\AuthTokenSchema;
use SymSvel\Module\Auth\Token\BoSessionLogout;
use SymSvel\Module\Auth\Token\DbalTokenStore;
use SymSvel\Module\Auth\Token\TokenFactory;
use SymSvel\Module\Auth\Token\TokenSubject;

final class BoSessionLogoutTest extends TestCase
{
    public function testOnlyMatchingAccessAndRefreshFamilyCanLogout(): void
    {
        $connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $schema = new Schema();
        AuthTokenSchema::apply($schema);
        foreach ($schema->toSql($connection->getDatabasePlatform()) as $sql) {
            $connection->executeStatement($sql);
        }

        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $store = new DbalTokenStore($connection);
        $factory = new TokenFactory();
        $first = $factory->issue('bo', null, $now);
        $second = $factory->issue('bo', null, $now);
        $app = $factory->issue('app', null, $now);
        $store->transaction(function () use ($store, $first, $second, $app, $now): void {
            $store->savePair(new TokenSubject('bo', 1), $first, $now);
            $store->savePair(new TokenSubject('bo', 1), $second, $now);
            $store->savePair(new TokenSubject('app', 2), $app, $now);
        });

        $logout = new BoSessionLogout($connection);
        $at = $now->modify('+1 minute');
        self::assertFalse($logout->logout($first->access->raw, $second->refresh->raw, $at));
        self::assertFalse($logout->logout($app->access->raw, $app->refresh->raw, $at));
        self::assertFalse($logout->logout('invalid', $first->refresh->raw, $at));
        self::assertSame(0, (int) $connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_access_tokens WHERE revoked_at IS NOT NULL'));

        self::assertTrue($logout->logout($first->access->raw, $first->refresh->raw, $at));
        self::assertFalse($logout->logout($first->access->raw, $first->refresh->raw, $at));
        self::assertSame(1, (int) $connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_access_tokens WHERE revoked_at IS NOT NULL'));
        self::assertSame(1, (int) $connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE revoked_at IS NOT NULL'));

        self::assertTrue($logout->logout($second->access->raw, $second->refresh->raw, $at));
        self::assertSame(2, (int) $connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_access_tokens WHERE revoked_at IS NOT NULL'));
        self::assertSame(0, (int) $connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_access_tokens WHERE context = ? AND revoked_at IS NOT NULL', ['app']));
    }
}
