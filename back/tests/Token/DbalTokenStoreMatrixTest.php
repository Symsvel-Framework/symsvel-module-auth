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
use SymSvel\Module\Auth\Token\TokenLogout;
use SymSvel\Module\Auth\Token\TokenIssuer;
use SymSvel\Module\Auth\Token\TokenSessionRevoker;
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
        $rotation = new TokenRotation($this->store, $factory, new RefreshTokenGuard(), new ActivePrincipal());

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
        $rotation = new TokenRotation($this->store, new TokenFactory(), new RefreshTokenGuard(), new ActivePrincipal());

        self::assertSame(RefreshDecision::Reject, $rotation->rotate(str_repeat('B', 43), 'bo', $now)->decision);
        self::assertSame(0, (int) $this->connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE revoked_at IS NOT NULL'));
    }

    public function testRevocationRollsBackWhenTransactionFails(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $pair = (new TokenIssuer($this->store, new TokenFactory()))
            ->issue(new TokenSubject('bo', 19), $now);

        try {
            $this->store->transaction(function () use ($now): void {
                $this->store->revokeSubject(new TokenSubject('bo', 19), $now);
                throw new \RuntimeException('forced revoke rollback');
            });
            self::fail('Expected rollback.');
        } catch (\RuntimeException $exception) {
            self::assertSame('forced revoke rollback', $exception->getMessage());
        }

        self::assertSame(19, (new AccessTokenVerifier($this->store))
            ->verify($pair->access->raw, 'bo', $now)?->id);
        self::assertSame(0, (int) $this->connection->fetchOne(
            'SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE revoked_at IS NOT NULL'
        ));
    }

    public function testIssueRollsBackWhenRefreshInsertFails(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $subject = new TokenSubject('bo', 31);
        $factory = new TokenFactory();
        $pair = $factory->issue('bo', null, $now);
        $this->connection->insert('symsvel_auth_refresh_tokens', [
            'context' => 'bo',
            'principal_id' => 31,
            'family_id' => $pair->familyId,
            'token_hash' => $pair->refresh->hash,
            'expires_at' => '2026-12-14 10:00:00.000000',
            'created_at' => '2026-11-14 10:00:00.000000',
        ]);

        try {
            $this->store->transaction(fn () => $this->store->savePair($subject, $pair, $now));
            self::fail('Expected duplicate refresh hash to reject transaction.');
        } catch (\Doctrine\DBAL\Exception\UniqueConstraintViolationException) {
            // Access insertion must have rolled back alongside the refresh failure.
        }

        self::assertSame(0, (int) $this->connection->fetchOne(
            'SELECT COUNT(*) FROM symsvel_auth_access_tokens WHERE token_hash = ?',
            [$pair->access->hash],
        ));
        self::assertSame(1, (int) $this->connection->fetchOne(
            'SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE token_hash = ?',
            [$pair->refresh->hash],
        ));
    }

    public function testRevokeAllSessionsIsScopedByPrincipalAndContext(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $issuer = new TokenIssuer($this->store, new TokenFactory());
        $boA1 = $issuer->issue(new TokenSubject('bo', 17), $now);
        $boA2 = $issuer->issue(new TokenSubject('bo', 17), $now);
        $boOther = $issuer->issue(new TokenSubject('bo', 18), $now);
        $appSameId = $issuer->issue(new TokenSubject('app', 17), $now);

        (new TokenSessionRevoker($this->store))->revokeAll(new TokenSubject('bo', 17), $now);
        $verifier = new AccessTokenVerifier($this->store);
        self::assertNull($verifier->verify($boA1->access->raw, 'bo', $now));
        self::assertNull($verifier->verify($boA2->access->raw, 'bo', $now));
        self::assertSame(18, $verifier->verify($boOther->access->raw, 'bo', $now)?->id);
        self::assertSame(17, $verifier->verify($appSameId->access->raw, 'app', $now)?->id);

        $rotation = new TokenRotation($this->store, new TokenFactory(), new RefreshTokenGuard(), new ActivePrincipal());
        self::assertSame(RefreshDecision::Reject, $rotation->rotate($boA1->refresh->raw, 'bo', $now)->decision);
        self::assertSame(RefreshDecision::Reject, $rotation->rotate($boA2->refresh->raw, 'bo', $now)->decision);
        self::assertSame(RefreshDecision::Rotate, $rotation->rotate($appSameId->refresh->raw, 'app', $now)->decision);
    }

    public function testIndependentSessionsOfSamePrincipalRemainValidAfterLogout(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $issuer = new TokenIssuer($this->store, new TokenFactory());
        $subject = new TokenSubject('bo', 17);
        $first = $issuer->issue($subject, $now);
        $second = $issuer->issue($subject, $now);
        $verifier = new AccessTokenVerifier($this->store);

        self::assertNotSame($first->familyId, $second->familyId);
        self::assertTrue((new TokenLogout($this->store))->logout($first->refresh->raw, 'bo', $now));
        self::assertNull($verifier->verify($first->access->raw, 'bo', $now));
        self::assertSame(17, $verifier->verify($second->access->raw, 'bo', $now)?->id);
    }

    public function testIssueRotateLogoutFullLifecycle(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $factory = new TokenFactory();
        $subject = new TokenSubject('app', 23);
        $initial = (new TokenIssuer($this->store, $factory))->issue($subject, $now);
        $verifier = new AccessTokenVerifier($this->store);

        self::assertSame(23, $verifier->verify($initial->access->raw, 'app', $now)?->id);
        self::assertNull($verifier->verify($initial->access->raw, 'bo', $now));

        $rotated = (new TokenRotation($this->store, $factory, new RefreshTokenGuard(), new ActivePrincipal()))
            ->rotate($initial->refresh->raw, 'app', $now->modify('+1 second'));
        self::assertSame(RefreshDecision::Rotate, $rotated->decision);
        self::assertNotNull($rotated->pair);
        self::assertSame($initial->familyId, $rotated->pair->familyId);
        self::assertNull($verifier->verify($initial->access->raw, 'app', $now->modify('+2 seconds')));
        self::assertSame(23, $verifier->verify($rotated->pair->access->raw, 'app', $now->modify('+2 seconds'))?->id);

        self::assertTrue((new TokenLogout($this->store))->logout($rotated->pair->refresh->raw, 'app', $now->modify('+3 seconds')));
        self::assertNull($verifier->verify($rotated->pair->access->raw, 'app', $now->modify('+4 seconds')));
        self::assertSame(2, (int) $this->connection->fetchOne(
            'SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE revoked_at IS NOT NULL'
        ));
    }

    public function testLogoutRevokesAccessAndRefreshInDatabase(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $factory = new TokenFactory();
        $pair = $factory->issue('bo', null, $now);
        $this->store->transaction(fn () => $this->store->savePair(new TokenSubject('bo', 10), $pair, $now));
        $logout = new TokenLogout($this->store);

        self::assertFalse($logout->logout($pair->refresh->raw, 'app', $now));
        self::assertSame(10, (new AccessTokenVerifier($this->store))->verify($pair->access->raw, 'bo', $now)?->id);
        self::assertTrue($logout->logout($pair->refresh->raw, 'bo', $now));
        self::assertNull((new AccessTokenVerifier($this->store))->verify($pair->access->raw, 'bo', $now));
        self::assertSame(1, (int) $this->connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE revoked_at IS NOT NULL'));
        self::assertFalse($logout->logout($pair->refresh->raw, 'bo', $now));
    }

    public function testExpiredTokensAreRejectedWithoutFamilyRevocation(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $factory = new TokenFactory();
        $pair = $factory->issue('bo', null, $now);
        $this->store->transaction(fn () => $this->store->savePair(new TokenSubject('bo', 10), $pair, $now));
        $verifier = new AccessTokenVerifier($this->store);

        self::assertNull($verifier->verify($pair->access->raw, 'bo', $pair->access->expiresAt));
        $result = (new TokenRotation($this->store, $factory, new RefreshTokenGuard(), new ActivePrincipal()))
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

        $result = (new TokenRotation($this->store, $factory, new RefreshTokenGuard(), new ActivePrincipal()))
            ->rotate($pair->refresh->raw, 'bo', $now->modify('+1 second'));
        self::assertSame(RefreshDecision::Rotate, $result->decision);
        self::assertNull($verifier->verify($pair->access->raw, 'bo', $now->modify('+2 seconds')));
        self::assertNotNull($result->pair);
        self::assertSame(10, $verifier->verify($result->pair->access->raw, 'bo', $now->modify('+2 seconds'))?->id);
    }

    public function testPasswordLoginAndAccountDeactivationAgainstRealDatabase(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $subject = new TokenSubject('bo', 17);
        $provider = new class($subject) implements \SymSvel\Module\Auth\Identity\PasswordPrincipal, \SymSvel\Module\Auth\Identity\PrincipalStatus {
            public bool $enabled = true;
            public int $statusCalls = 0;

            public function __construct(private TokenSubject $subject) {}

            public function authenticate(string $context, string $identifier, string $password): ?TokenSubject
            {
                return $this->enabled
                    && $context === 'bo'
                    && $identifier === 'admin@example.test'
                    && hash_equals('correct-password', $password)
                    ? $this->subject
                    : null;
            }

            public function isActive(TokenSubject $subject): bool
            {
                ++$this->statusCalls;

                return $this->enabled && $subject->context === $this->subject->context && $subject->id === $this->subject->id;
            }
        };

        $login = new \SymSvel\Module\Auth\Identity\PasswordLogin(
            $provider,
            new TokenIssuer($this->store, new TokenFactory()),
        );
        $resolver = new \SymSvel\Module\Auth\Identity\AuthenticatedTokenResolver(
            new AccessTokenVerifier($this->store),
            $provider,
        );

        self::assertNull($login->login('bo', 'admin@example.test', 'incorrect', $now));
        self::assertSame(0, (int) $this->connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_refresh_tokens'));

        $pair = $login->login('bo', 'admin@example.test', 'correct-password', $now);
        self::assertNotNull($pair);
        self::assertSame(17, $resolver->resolve($pair->access->raw, 'bo', $now)?->id);
        self::assertNull($resolver->resolve($pair->access->raw, 'app', $now));
        self::assertSame(1, $provider->statusCalls);

        $provider->enabled = false;
        self::assertNull($resolver->resolve($pair->access->raw, 'bo', $now));
        self::assertNull($login->login('bo', 'admin@example.test', 'correct-password', $now));
        self::assertSame(2, $provider->statusCalls);
        self::assertSame(1, (int) $this->connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_refresh_tokens'));

        (new TokenSessionRevoker($this->store))->revokeAll($subject, $now);
        self::assertNull((new AccessTokenVerifier($this->store))->verify($pair->access->raw, 'bo', $now));
    }

    public function testAccessExpiryBoundaryAndRefreshExpiryDoNotExtendAccess(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $factory = new TokenFactory();
        $subject = new TokenSubject('bo', 44);
        $pair = (new TokenIssuer($this->store, $factory))->issue($subject, $now);
        $verifier = new AccessTokenVerifier($this->store);

        self::assertSame(44, $verifier->verify($pair->access->raw, 'bo', $pair->access->expiresAt->modify('-1 microsecond'))?->id);
        self::assertNull($verifier->verify($pair->access->raw, 'bo', $pair->access->expiresAt));
        self::assertNull($verifier->verify($pair->access->raw, 'bo', $pair->access->expiresAt->modify('+1 microsecond')));

        $rotation = new TokenRotation($this->store, $factory, new RefreshTokenGuard(), new ActivePrincipal());
        self::assertSame(
            RefreshDecision::Reject,
            $rotation->rotate($pair->refresh->raw, 'bo', $pair->refresh->expiresAt)->decision,
        );
        self::assertSame(1, (int) $this->connection->fetchOne(
            'SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE used_at IS NULL AND revoked_at IS NULL',
        ));
    }

    public function testDisabledPrincipalCannotRefreshAndWholeFamilyIsRevokedInDatabase(): void
    {
        $now = new \DateTimeImmutable('2026-11-14T10:00:00+00:00');
        $subject = new TokenSubject('bo', 51);
        $issuer = new TokenIssuer($this->store, new TokenFactory());
        $pair = $issuer->issue($subject, $now);
        $other = $issuer->issue(new TokenSubject('bo', 52), $now);
        $principals = new ActivePrincipal();
        $principals->active = false;

        $result = (new TokenRotation($this->store, new TokenFactory(), new RefreshTokenGuard(), $principals))
            ->rotate($pair->refresh->raw, 'bo', $now->modify('+1 second'));

        self::assertSame(RefreshDecision::Reject, $result->decision);
        self::assertNull($result->pair);
        self::assertSame(1, (int) $this->connection->fetchOne(
            'SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE principal_id = ? AND revoked_at IS NOT NULL',
            [51],
        ));
        self::assertSame(1, (int) $this->connection->fetchOne(
            'SELECT COUNT(*) FROM symsvel_auth_access_tokens WHERE principal_id = ? AND revoked_at IS NOT NULL',
            [51],
        ));
        self::assertSame(0, (int) $this->connection->fetchOne(
            'SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE principal_id = ? AND used_at IS NOT NULL',
            [51],
        ));
        self::assertNull((new AccessTokenVerifier($this->store))->verify($pair->access->raw, 'bo', $now));
        self::assertSame(52, (new AccessTokenVerifier($this->store))->verify($other->access->raw, 'bo', $now)?->id);
    }

}
