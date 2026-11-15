<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Identity\ContextPasswordResetIdentity;
use SymSvel\Module\Auth\Identity\PasswordResetCompletion;
use SymSvel\Module\Auth\Identity\PasswordResetIdentity;
use SymSvel\Module\Auth\Schema\AuthTokenSchema;
use SymSvel\Module\Auth\Schema\PasswordResetSchema;
use SymSvel\Module\Auth\Token\DbalPasswordResetStore;
use SymSvel\Module\Auth\Token\DbalTokenStore;
use SymSvel\Module\Auth\Token\PasswordResetToken;
use SymSvel\Module\Auth\Token\TokenFactory;
use SymSvel\Module\Auth\Token\TokenSubject;

final class PasswordResetCompletionTest extends TestCase
{
    public function testSuccessRevokesSessionsAndRejectsReplay(): void
    {
        [$connection, $resets, $sessions, $completion, $provider] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        $subject = new TokenSubject('bo', 5);
        $token = PasswordResetToken::issue('bo', $now);
        $resets->save($subject, $token, $now);
        $pair = (new TokenFactory())->issue('bo', null, $now);
        $sessions->savePair($subject, $pair, $now);
        self::assertTrue($completion->complete('bo', $token->raw, 'long-enough-password', $now));
        self::assertTrue(password_verify('long-enough-password', (string) $connection->fetchOne('SELECT password_hash FROM test_reset_accounts WHERE id = 5')));
        self::assertSame(1, (int) $connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_password_reset_tokens WHERE used_at IS NOT NULL'));
        self::assertSame(1, (int) $connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_access_tokens WHERE revoked_at IS NOT NULL'));
        self::assertSame(1, (int) $connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE revoked_at IS NOT NULL'));
        self::assertFalse($completion->complete('bo', $token->raw, 'another-long-password', $now));
        self::assertFalse($completion->complete('app', $token->raw, 'another-long-password', $now));
    }

    public function testFailedPasswordUpdateRollsBackConsumption(): void
    {
        [$connection, $resets, , $completion, $provider] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        $token = PasswordResetToken::issue('bo', $now);
        $resets->save(new TokenSubject('bo', 5), $token, $now);
        $originalHash = (string) $connection->fetchOne('SELECT password_hash FROM test_reset_accounts WHERE id = 5');
        $provider->allow = false;
        self::assertFalse($completion->complete('bo', $token->raw, 'long-enough-password', $now));
        self::assertSame(0, (int) $connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_password_reset_tokens WHERE used_at IS NOT NULL'));
        self::assertSame($originalHash, $connection->fetchOne('SELECT password_hash FROM test_reset_accounts WHERE id = 5'));
        $provider->allow = true;
        self::assertTrue($completion->complete('bo', $token->raw, 'long-enough-password', $now));
    }

    private function fixture(): array
    {
        $connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $schema = new Schema();
        AuthTokenSchema::apply($schema);
        PasswordResetSchema::apply($schema);
        foreach ($schema->toSql($connection->getDatabasePlatform()) as $sql) {
            $connection->executeStatement($sql);
        }
        $connection->executeStatement('CREATE TABLE test_reset_accounts (id INTEGER PRIMARY KEY, password_hash VARCHAR(255) NOT NULL, enabled INTEGER NOT NULL)');
        $connection->insert('test_reset_accounts', ['id' => 5, 'password_hash' => password_hash('original-password', PASSWORD_ARGON2ID), 'enabled' => 1]);
        $provider = new class($connection) implements PasswordResetIdentity {
            public function __construct(private readonly \Doctrine\DBAL\Connection $connection) {}
            public bool $allow = true;
            public function authContext(): string { return 'bo'; }
            public function findResetSubject(string $identifier): ?TokenSubject { return new TokenSubject('bo', 5); }
            public function recoveryEmail(TokenSubject $subject): ?string { return $subject->context === 'bo' ? 'admin@example.test' : null; }
            public function replacePassword(TokenSubject $subject, string $newPasswordHash): bool
            {
                if (!$this->allow) { return false; }
                return $this->connection->executeStatement('UPDATE test_reset_accounts SET password_hash = ? WHERE id = ? AND enabled = 1', [$newPasswordHash, $subject->id]) === 1;
            }
        };
        $resets = new DbalPasswordResetStore($connection);
        $sessions = new DbalTokenStore($connection);
        return [$connection, $resets, $sessions, new PasswordResetCompletion(
            $connection, $resets, new ContextPasswordResetIdentity([$provider]), $sessions,
        ), $provider];
    }
}
