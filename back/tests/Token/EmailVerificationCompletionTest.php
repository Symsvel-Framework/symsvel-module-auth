<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Identity\ContextEmailVerificationIdentity;
use SymSvel\Module\Auth\Identity\EmailVerificationCompletion;
use SymSvel\Module\Auth\Identity\EmailVerificationIdentity;
use SymSvel\Module\Auth\Schema\EmailVerificationSchema;
use SymSvel\Module\Auth\Token\DbalEmailVerificationStore;
use SymSvel\Module\Auth\Token\EmailVerificationToken;
use SymSvel\Module\Auth\Token\TokenSubject;

final class EmailVerificationCompletionTest extends TestCase
{
    public function testConfirmIsAtomicAndRejectsReplaysAndWrongContext(): void
    {
        [$completion, $store, $db] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        $token = EmailVerificationToken::issue('bo', $now);
        $store->save(new TokenSubject('bo', 7), 'admin@example.test', $token, $now);

        self::assertFalse($completion->complete('app', $token->raw, $now));
        self::assertNull($db->fetchOne('SELECT verified_at FROM test_accounts WHERE id = 7') ?: null);

        self::assertTrue($completion->complete('bo', $token->raw, $now));
        self::assertNotFalse($db->fetchOne('SELECT verified_at FROM test_accounts WHERE id = 7'));
        self::assertFalse($completion->complete('bo', $token->raw, $now));
    }

    public function testChangedEmailRollsBackTokenConsumption(): void
    {
        [$completion, $store, $db] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        $token = EmailVerificationToken::issue('bo', $now);
        $store->save(new TokenSubject('bo', 7), 'admin@example.test', $token, $now);
        $db->executeStatement('UPDATE test_accounts SET email = ? WHERE id = 7', ['changed@example.test']);
        self::assertFalse($completion->complete('bo', $token->raw, $now));
        self::assertNull($db->fetchOne('SELECT used_at FROM symsvel_auth_email_verification_tokens WHERE token_hash = ?', [$token->hash]) ?: null);
        self::assertNull($db->fetchOne('SELECT verified_at FROM test_accounts WHERE id = 7') ?: null);

        $db->executeStatement('UPDATE test_accounts SET email = ? WHERE id = 7', ['admin@example.test']);
        self::assertTrue($completion->complete('bo', $token->raw, $now));
    }

    public function testDisabledAccountIsNeverConfirmed(): void
    {
        [$completion, $store, $db] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        $token = EmailVerificationToken::issue('bo', $now);
        $store->save(new TokenSubject('bo', 7), 'admin@example.test', $token, $now);
        $db->executeStatement('UPDATE test_accounts SET enabled = 0 WHERE id = 7');

        self::assertFalse($completion->complete('bo', $token->raw, $now));
        self::assertNull($db->fetchOne('SELECT used_at FROM symsvel_auth_email_verification_tokens WHERE token_hash = ?', [$token->hash]) ?: null);
    }

    /** @return array{EmailVerificationCompletion, DbalEmailVerificationStore, Connection} */
    private function fixture(): array
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $db = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $schema = new Schema();
        EmailVerificationSchema::apply($schema);
        foreach ($schema->toSql($db->getDatabasePlatform()) as $sql) {
            $db->executeStatement($sql);
        }

        $db->executeStatement('CREATE TABLE test_accounts (id INTEGER PRIMARY KEY, email VARCHAR(254) NOT NULL, enabled BOOLEAN NOT NULL, verified_at DATETIME NULL)');
        $db->insert('test_accounts', ['id' => 7, 'email' => 'admin@example.test', 'enabled' => true, 'verified_at' => null]);

        $owner = new class($db) implements EmailVerificationIdentity {
            public function __construct(private Connection $db) {}
            public function authContext(): string { return 'bo'; }
            public function pendingVerificationEmail(TokenSubject $subject): ?string
            {
                if ($subject->context !== 'bo') {
                    return null;
                }
                $email = $this->db->fetchOne(
                    'SELECT email FROM test_accounts WHERE id = ? AND enabled = ? AND verified_at IS NULL',
                    [$subject->id, true],
                );
                return is_string($email) ? $email : null;
            }
            public function confirmEmail(TokenSubject $subject, string $emailHash, \DateTimeImmutable $now): bool
            {
                if ($subject->context !== 'bo') {
                    return false;
                }
                $email = $this->db->fetchOne('SELECT email FROM test_accounts WHERE id = ? AND enabled = ?', [$subject->id, true]);
                if (!is_string($email) || !hash_equals(hash('sha256', strtolower(trim($email))), $emailHash)) {
                    return false;
                }
                return $this->db->executeStatement(
                    'UPDATE test_accounts SET verified_at = ? WHERE id = ? AND enabled = ? AND email = ? AND verified_at IS NULL',
                    [$now->format('Y-m-d H:i:s'), $subject->id, true, $email],
                ) === 1;
            }
        };

        $store = new DbalEmailVerificationStore($db);
        $completion = new EmailVerificationCompletion($db, $store, new ContextEmailVerificationIdentity([$owner]));

        return [$completion, $store, $db];
    }
}
