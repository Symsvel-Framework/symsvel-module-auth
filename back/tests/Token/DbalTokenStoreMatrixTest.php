<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Schema\AuthTokenSchema;
use SymSvel\Module\Auth\Token\DbalTokenStore;
use SymSvel\Module\Auth\Token\AccessTokenVerifier;
use SymSvel\Module\Auth\Token\RefreshDecision;
use SymSvel\Module\Auth\Token\RefreshTokenGuard;
use SymSvel\Module\Auth\Token\TokenFactory;
use SymSvel\Module\Auth\Token\TokenRotation;
use SymSvel\Module\Auth\Token\TokenSubject;

/**
 * Set SYMSVEL_AUTH_TEST_DATABASE_URL to test a real PostgreSQL/MySQL/MariaDB
 * database. The database MUST be dedicated to tests and may be modified.
 */
final class DbalTokenStoreMatrixTest extends TestCase
{
    private Connection $connection;
    private DbalTokenStore $store;
    /** @var list<string> */
    private array $createdTables = [];

    protected function setUp(): void
    {
        $url = getenv('SYMSVEL_AUTH_TEST_DATABASE_URL');
        $this->connection = $url
            ? DriverManager::getConnection(['url' => $url])
            : DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);

        $schema = new Schema();
        AuthTokenSchema::apply($schema);
        $manager = $this->connection->createSchemaManager();
        foreach (['symsvel_auth_access_tokens', 'symsvel_auth_refresh_tokens'] as $table) {
            if ($manager->tablesExist([$table])) {
                self::fail('Auth test tables already exist: use a dedicated empty database.');
            }
        }
        foreach ($schema->toSql($this->connection->getDatabasePlatform()) as $sql) {
            $this->connection->executeStatement($sql);
            foreach (['symsvel_auth_access_tokens', 'symsvel_auth_refresh_tokens'] as $table) {
                if (!in_array($table, $this->createdTables, true) && $manager->tablesExist([$table])) {
                    $this->createdTables[] = $table;
                }
            }
        }
        $this->store = new DbalTokenStore($this->connection);
    }

    protected function tearDown(): void
    {
        if (!isset($this->connection)) {
            return;
        }
        foreach (array_reverse($this->createdTables) as $table) {
            if ($this->connection->createSchemaManager()->tablesExist([$table])) {
                $this->connection->executeStatement('DROP TABLE '.$table);
            }
        }
        $this->connection->close();
    }

    public function testRotationReplayAndContextIsolation(): void
    {
        $factory = new TokenFactory();
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $pair = $factory->issue('bo', null, $now);
        $this->store->transaction(fn () => $this->store->savePair(new TokenSubject('bo', 10), $pair, $now));
        $rotation = new TokenRotation($this->store, $factory, new RefreshTokenGuard());

        self::assertSame(RefreshDecision::Reject, $rotation->rotate($pair->refresh->raw, 'app', $now)->decision);
        self::assertSame(RefreshDecision::Rotate, $rotation->rotate($pair->refresh->raw, 'bo', $now->modify('+1 second'))->decision);
        self::assertSame(RefreshDecision::RevokeFamily, $rotation->rotate($pair->refresh->raw, 'bo', $now->modify('+2 seconds'))->decision);
        self::assertSame(2, (int) $this->connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_access_tokens WHERE revoked_at IS NOT NULL'));
    }

    public function testTransactionRollsBackBothTables(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $pair = (new TokenFactory())->issue('bo', null, $now);
        try {
            $this->store->transaction(function () use ($pair, $now): void {
                $this->store->savePair(new TokenSubject('bo', 10), $pair, $now);
                throw new \RuntimeException('forced rollback');
            });
            self::fail('Expected rollback exception.');
        } catch (\RuntimeException $exception) {
            self::assertSame('forced rollback', $exception->getMessage());
        }
        self::assertSame(0, (int) $this->connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_access_tokens'));
        self::assertSame(0, (int) $this->connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_refresh_tokens'));
    }

    public function testIndependentFamiliesAreNotRevokedTogether(): void
    {
        $factory = new TokenFactory();
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $first = $factory->issue('bo', null, $now);
        $second = $factory->issue('bo', null, $now);
        $this->store->transaction(function () use ($first, $second, $now): void {
            $this->store->savePair(new TokenSubject('bo', 10), $first, $now);
            $this->store->savePair(new TokenSubject('bo', 10), $second, $now);
        });
        $this->store->transaction(fn () => $this->store->revokeFamily('bo', $first->familyId, $now));
        self::assertSame(2, (int) $this->connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_access_tokens WHERE revoked_at IS NULL') + (int) $this->connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE revoked_at IS NULL'));
    }
    public function testUnknownRefreshIsRejectedWithoutChangingStoredTokens(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $pair = (new TokenFactory())->issue('bo', null, $now);
        $this->store->transaction(fn () => $this->store->savePair(new TokenSubject('bo', 10), $pair, $now));
        $rotation = new TokenRotation($this->store, new TokenFactory(), new RefreshTokenGuard());

        self::assertSame(RefreshDecision::Reject, $rotation->rotate(str_repeat('B', 43), 'bo', $now)->decision);
        self::assertSame(0, (int) $this->connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE revoked_at IS NOT NULL'));
    }

    public function testExpiredTokensAreRejectedWithoutFamilyRevocation(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $factory = new TokenFactory();
        $pair = $factory->issue('bo', null, $now);
        $this->store->transaction(fn () => $this->store->savePair(new TokenSubject('bo', 10), $pair, $now));
        $verifier = new AccessTokenVerifier($this->store);

        self::assertNull($verifier->verify($pair->access->raw, 'bo', $pair->access->expiresAt));
        $result = (new TokenRotation($this->store, $factory, new RefreshTokenGuard()))
            ->rotate($pair->refresh->raw, 'bo', $pair->refresh->expiresAt);
        self::assertSame(RefreshDecision::Reject, $result->decision);
        self::assertSame(0, (int) $this->connection->fetchOne(
            'SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE revoked_at IS NOT NULL'
        ));
    }

    public function testAccessValidationBeforeAndAfterRotation(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $factory = new TokenFactory();
        $pair = $factory->issue('bo', null, $now);
        $this->store->transaction(fn () => $this->store->savePair(new TokenSubject('bo', 10), $pair, $now));
        $verifier = new AccessTokenVerifier($this->store);

        self::assertSame(10, $verifier->verify($pair->access->raw, 'bo', $now)?->id);
        self::assertNull($verifier->verify($pair->access->raw, 'app', $now));

        $result = (new TokenRotation($this->store, $factory, new RefreshTokenGuard()))
            ->rotate($pair->refresh->raw, 'bo', $now->modify('+1 second'));
        self::assertSame(RefreshDecision::Rotate, $result->decision);
        self::assertNull($verifier->verify($pair->access->raw, 'bo', $now->modify('+2 seconds')));
        self::assertNotNull($result->pair);
        self::assertSame(10, $verifier->verify($result->pair->access->raw, 'bo', $now->modify('+2 seconds'))?->id);
    }

}
