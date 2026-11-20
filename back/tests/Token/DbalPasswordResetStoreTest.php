<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Schema\PasswordResetSchema;
use SymSvel\Module\Auth\Token\DbalPasswordResetStore;
use SymSvel\Module\Auth\Token\PasswordResetToken;
use SymSvel\Module\Auth\Token\TokenSubject;

final class DbalPasswordResetStoreTest extends TestCase
{
    public function testOneTimeConsumptionAndContextIsolation(): void
    {
        $connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $schema = new Schema();
        PasswordResetSchema::apply($schema);
        foreach ($schema->toSql($connection->getDatabasePlatform()) as $sql) {
            $connection->executeStatement($sql);
        }
        $store = new DbalPasswordResetStore($connection);
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        $token = PasswordResetToken::issue('bo', $now);
        $store->save(new TokenSubject('bo', 7), $token, $now);
        self::assertNull($store->consume('app', $token->raw, $now));
        self::assertNull($store->consume('bo', 'invalid', $now));
        self::assertSame(7, $store->consume('bo', $token->raw, $now));
        self::assertNull($store->consume('bo', $token->raw, $now));
        $expired = PasswordResetToken::issue('app', $now, 1);
        $store->save(new TokenSubject('app', 8), $expired, $now);
        self::assertNull($store->consume('app', $expired->raw, $now->modify('+2 seconds')));
    }

    public function testRejectsMismatchedContext(): void
    {
        $connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $store = new DbalPasswordResetStore($connection);
        $this->expectException(\InvalidArgumentException::class);
        $store->save(new TokenSubject('app', 1), PasswordResetToken::issue('bo', new \DateTimeImmutable()), new \DateTimeImmutable());
    }
}
