<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\DBAL\Tools\DsnParser;
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

/** Runs against SQLite by default and the dedicated database supplied by CI. */
final class PasswordResetMatrixTest extends TestCase
{
    private Connection $connection;

    protected function setUp(): void
    {
        $url = getenv('SYMSVEL_AUTH_TEST_DATABASE_URL');
        $this->connection = $url
            ? DriverManager::getConnection((new DsnParser(['postgresql' => 'pdo_pgsql', 'mysql' => 'pdo_mysql', 'mariadb' => 'pdo_mysql']))->parse($url))
            : DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $schema = new Schema();
        AuthTokenSchema::apply($schema);
        PasswordResetSchema::apply($schema);
        $accounts = $schema->createTable('symsvel_auth_test_reset_accounts');
        $accounts->addColumn('id', 'integer');
        $accounts->addColumn('password_hash', 'string', ['length' => 255]);
        $accounts->addColumn('enabled', 'boolean');
        $accounts->setPrimaryKey(['id']);
        foreach (['symsvel_auth_access_tokens', 'symsvel_auth_refresh_tokens', 'symsvel_auth_password_reset_tokens', 'symsvel_auth_test_reset_accounts'] as $table) {
            if ($this->connection->createSchemaManager()->tablesExist([$table])) {
                self::fail('Password reset matrix requires an empty dedicated test database.');
            }
        }
        foreach ($schema->toSql($this->connection->getDatabasePlatform()) as $sql) {
            $this->connection->executeStatement($sql);
        }
    }

    protected function tearDown(): void
    {
        if (!isset($this->connection)) {
            return;
        }
        foreach (['symsvel_auth_test_reset_accounts', 'symsvel_auth_password_reset_tokens', 'symsvel_auth_refresh_tokens', 'symsvel_auth_access_tokens'] as $table) {
            if ($this->connection->createSchemaManager()->tablesExist([$table])) {
                $this->connection->executeStatement('DROP TABLE '.$table);
            }
        }
        $this->connection->close();
    }

    public function testResetPersistenceReplayAndRollback(): void
    {
        $db = $this->connection;
        $original = password_hash('original-password', PASSWORD_ARGON2ID);
        $db->insert('symsvel_auth_test_reset_accounts', ['id' => 71, 'password_hash' => $original, 'enabled' => true]);
        $owner = new class($db) implements PasswordResetIdentity {
            public bool $allow = true;
            public function __construct(private Connection $db) {}
            public function authContext(): string { return 'bo'; }
            public function findResetSubject(string $identifier): ?TokenSubject { return null; }
            public function recoveryEmail(TokenSubject $subject): ?string { return $subject->context === 'bo' ? 'admin@example.test' : null; }
            public function replacePassword(TokenSubject $subject, string $newPasswordHash): bool
            {
                if (!$this->allow || $subject->context !== 'bo') { return false; }
                return $this->db->executeStatement(
                    'UPDATE symsvel_auth_test_reset_accounts SET password_hash = ? WHERE id = ? AND enabled = ?',
                    [$newPasswordHash, $subject->id, true],
                    [\Doctrine\DBAL\ParameterType::STRING, \Doctrine\DBAL\ParameterType::INTEGER, \Doctrine\DBAL\ParameterType::BOOLEAN],
                ) === 1;
            }
        };
        $resets = new DbalPasswordResetStore($db);
        $sessions = new DbalTokenStore($db);
        $completion = new PasswordResetCompletion($db, $resets, new ContextPasswordResetIdentity([$owner]), $sessions);
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        $subject = new TokenSubject('bo', 71);
        $token = PasswordResetToken::issue('bo', $now);
        $resets->save($subject, $token, $now);
        $sessions->savePair($subject, (new TokenFactory())->issue('bo', null, $now), $now);

        $owner->allow = false;
        self::assertFalse($completion->complete('bo', $token->raw, 'new-password-long-enough', $now));
        self::assertSame($original, $db->fetchOne('SELECT password_hash FROM symsvel_auth_test_reset_accounts WHERE id = 71'));
        self::assertSame(0, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_password_reset_tokens WHERE used_at IS NOT NULL'));
        self::assertSame(0, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_access_tokens WHERE revoked_at IS NOT NULL'));

        $owner->allow = true;
        self::assertFalse($completion->complete('app', $token->raw, 'new-password-long-enough', $now));
        self::assertTrue($completion->complete('bo', $token->raw, 'new-password-long-enough', $now));
        self::assertTrue(password_verify('new-password-long-enough', (string) $db->fetchOne('SELECT password_hash FROM symsvel_auth_test_reset_accounts WHERE id = 71')));
        self::assertSame(1, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_password_reset_tokens WHERE used_at IS NOT NULL'));
        self::assertSame(1, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_access_tokens WHERE revoked_at IS NOT NULL'));
        self::assertSame(1, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE revoked_at IS NOT NULL'));
        self::assertFalse($completion->complete('bo', $token->raw, 'another-long-password', $now));
    }
}
