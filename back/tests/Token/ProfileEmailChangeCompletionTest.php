<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Identity\ContextProfileEmailOwners;
use SymSvel\Module\Auth\Identity\ProfileEmailChangeCompletion;
use SymSvel\Module\Auth\Identity\ProfileEmailOwner;
use SymSvel\Module\Auth\Schema\AuthTokenSchema;
use SymSvel\Module\Auth\Schema\ProfileEmailChangeSchema;
use SymSvel\Module\Auth\Token\DbalProfileEmailChangeStore;
use SymSvel\Module\Auth\Token\DbalTokenStore;
use SymSvel\Module\Auth\Token\EmailVerificationToken;
use SymSvel\Module\Auth\Token\TokenFactory;
use SymSvel\Module\Auth\Token\TokenSubject;

final class ProfileEmailChangeCompletionTest extends TestCase
{
    public function testConfirmsOnlyNewMailboxAndRevokesBothSessionKinds(): void
    {
        [$db, $store, $completion, $sessions] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-19T13:00:00+00:00');
        $subject = new TokenSubject('bo', 7);
        $pair = (new TokenFactory())->issue('bo', null, $now);
        $sessions->savePair($subject, $pair, $now);
        $token = EmailVerificationToken::issue('bo', $now);
        $store->save($subject, 'old@example.test', 'new@example.test', $token, $now);

        // The existing account remains usable until the recipient confirms.
        self::assertSame('old@example.test', $db->fetchOne('SELECT email FROM test_accounts WHERE id = 7'));
        self::assertFalse($completion->complete('app', $token->raw, $now));
        self::assertTrue($completion->complete('bo', $token->raw, $now));
        self::assertSame('new@example.test', $db->fetchOne('SELECT email FROM test_accounts WHERE id = 7'));
        self::assertSame(1, (int) $db->fetchOne(
            'SELECT COUNT(*) FROM symsvel_auth_access_tokens WHERE revoked_at IS NOT NULL',
        ));
        self::assertSame(1, (int) $db->fetchOne(
            'SELECT COUNT(*) FROM symsvel_auth_refresh_tokens WHERE revoked_at IS NOT NULL',
        ));
        self::assertFalse($completion->complete('bo', $token->raw, $now));
    }

    public function testOldMailboxChangedSinceRequestRollsBackTheToken(): void
    {
        [$db, $store, $completion] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-19T13:00:00+00:00');
        $token = EmailVerificationToken::issue('bo', $now);
        $store->save(new TokenSubject('bo', 7), 'old@example.test', 'new@example.test', $token, $now);
        $db->executeStatement('UPDATE test_accounts SET email = ? WHERE id = 7', ['changed@example.test']);

        self::assertFalse($completion->complete('bo', $token->raw, $now));
        self::assertSame('changed@example.test', $db->fetchOne('SELECT email FROM test_accounts WHERE id = 7'));
        self::assertNull($db->fetchOne(
            'SELECT used_at FROM symsvel_auth_profile_email_changes WHERE token_hash = ?',
            [$token->hash],
        ) ?: null);
    }

    public function testEmailConflictCannotPartiallyConsumeTheToken(): void
    {
        [$db, $store, $completion] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-19T13:00:00+00:00');
        $token = EmailVerificationToken::issue('bo', $now);
        $store->save(new TokenSubject('bo', 7), 'old@example.test', 'reserved@example.test', $token, $now);
        self::assertFalse($completion->complete('bo', $token->raw, $now));
        self::assertSame('old@example.test', $db->fetchOne('SELECT email FROM test_accounts WHERE id = 7'));
        self::assertNull($db->fetchOne(
            'SELECT used_at FROM symsvel_auth_profile_email_changes WHERE token_hash = ?',
            [$token->hash],
        ) ?: null);
    }

    public function testExpiredAndInvalidSecretsAreRejected(): void
    {
        [$db, $store, $completion] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-19T13:00:00+00:00');
        $token = EmailVerificationToken::issue('bo', $now, 60);
        $store->save(new TokenSubject('bo', 7), 'old@example.test', 'new@example.test', $token, $now);

        self::assertFalse($completion->complete('bo', $token->raw, $now->modify('+61 seconds')));
        self::assertFalse($completion->complete('bo', 'invalid', $now));
        self::assertSame('old@example.test', $db->fetchOne('SELECT email FROM test_accounts WHERE id = 7'));
    }

    /** @return array{Connection, DbalProfileEmailChangeStore, ProfileEmailChangeCompletion, DbalTokenStore} */
    private function fixture(): array
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $db = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $schema = new Schema();
        ProfileEmailChangeSchema::apply($schema);
        AuthTokenSchema::apply($schema);
        foreach ($schema->toSql($db->getDatabasePlatform()) as $sql) {
            $db->executeStatement($sql);
        }
        $db->executeStatement(
            'CREATE TABLE test_accounts (id INTEGER PRIMARY KEY, email VARCHAR(254) NOT NULL UNIQUE, enabled BOOLEAN NOT NULL)',
        );
        $db->insert('test_accounts', ['id' => 7, 'email' => 'old@example.test', 'enabled' => true]);
        $db->insert('test_accounts', ['id' => 8, 'email' => 'reserved@example.test', 'enabled' => true]);
        $owner = new class($db) implements ProfileEmailOwner {
            public function __construct(private Connection $db) {}
            public function authContext(): string { return 'bo'; }
            public function confirmNewEmail(
                TokenSubject $subject, string $oldEmailHash, string $newEmail, \DateTimeImmutable $now,
            ): bool {
                if ($subject->context !== 'bo') return false;
                $old = $this->db->fetchOne(
                    'SELECT email FROM test_accounts WHERE id = ? AND enabled = ?',
                    [$subject->id, true],
                );
                if (!is_string($old) || !hash_equals(hash('sha256', $old), $oldEmailHash)) {
                    return false;
                }
                return $this->db->executeStatement(
                    'UPDATE test_accounts SET email = ? WHERE id = ? AND email = ? AND enabled = ?',
                    [$newEmail, $subject->id, $old, true],
                ) === 1;
            }
        };
        $store = new DbalProfileEmailChangeStore($db);
        $sessions = new DbalTokenStore($db);
        $completion = new ProfileEmailChangeCompletion(
            $db, $store, new ContextProfileEmailOwners([$owner]), $sessions,
        );
        return [$db, $store, $completion, $sessions];
    }
}
