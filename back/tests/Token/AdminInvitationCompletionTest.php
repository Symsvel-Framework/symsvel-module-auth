<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Identity\AdminInvitationCompletion;
use SymSvel\Module\Auth\Identity\AdminInvitationIdentity;
use SymSvel\Module\Auth\Identity\AdminInvitationOwners;
use SymSvel\Module\Auth\Schema\AdminInvitationSchema;
use SymSvel\Module\Auth\Token\AdminInvitationToken;
use SymSvel\Module\Auth\Token\DbalAdminInvitationStore;

final class AdminInvitationCompletionTest extends TestCase
{
    public function testActivationIsAtomicEmailBoundAndSingleUse(): void
    {
        [$completion, $tokens, $db] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-16T12:00:00+00:00');
        $first = AdminInvitationToken::issue($now);
        $tokens->save(7, 'admin@example.test', $first, $now);

        $db->executeStatement("UPDATE test_invited_admins SET email = 'changed@example.test' WHERE id = 7");
        self::assertFalse($completion->complete($first->raw, 'new-long-password', $now));
        self::assertNull($db->fetchOne('SELECT used_at FROM symsvel_auth_admin_invitations WHERE token_hash = ?', [$first->hash]) ?: null);
        self::assertNull($db->fetchOne('SELECT verified_at FROM test_invited_admins WHERE id = 7') ?: null);

        $db->executeStatement("UPDATE test_invited_admins SET email = 'admin@example.test' WHERE id = 7");
        self::assertTrue($completion->complete($first->raw, 'new-long-password', $now));
        self::assertTrue(password_verify('new-long-password', (string) $db->fetchOne('SELECT password_hash FROM test_invited_admins WHERE id = 7')));
        self::assertNotFalse($db->fetchOne('SELECT verified_at FROM test_invited_admins WHERE id = 7'));
        self::assertFalse($completion->complete($first->raw, 'another-password', $now));
    }

    public function testDisabledAccountRollsBackAndPasswordIsUnchanged(): void
    {
        [$completion, $tokens, $db] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-16T12:00:00+00:00');
        $token = AdminInvitationToken::issue($now);
        $tokens->save(7, 'admin@example.test', $token, $now);
        $db->executeStatement('UPDATE test_invited_admins SET enabled = 0 WHERE id = 7');
        self::assertFalse($completion->complete($token->raw, 'new-long-password', $now));
        self::assertSame('pending-invitation', $db->fetchOne('SELECT password_hash FROM test_invited_admins WHERE id = 7'));
        self::assertNull($db->fetchOne('SELECT used_at FROM symsvel_auth_admin_invitations WHERE token_hash = ?', [$token->hash]) ?: null);
    }

    /** @return array{AdminInvitationCompletion, DbalAdminInvitationStore, Connection} */
    private function fixture(): array
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $db = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $schema = new Schema();
        AdminInvitationSchema::apply($schema);
        foreach ($schema->toSql($db->getDatabasePlatform()) as $sql) {
            $db->executeStatement($sql);
        }
        $db->executeStatement('CREATE TABLE test_invited_admins (id INTEGER PRIMARY KEY, email VARCHAR(254), enabled BOOLEAN, verified_at DATETIME NULL, password_hash VARCHAR(255))');
        $db->insert('test_invited_admins', ['id' => 7, 'email' => 'admin@example.test', 'enabled' => 1, 'verified_at' => null, 'password_hash' => 'pending-invitation']);

        $owner = new class($db) implements AdminInvitationIdentity {
            public function __construct(private Connection $db) {}
            public function activateInvitation(int $adminId, string $emailHash, string $passwordHash, \DateTimeImmutable $now): bool
            {
                $email = $this->db->fetchOne(
                    'SELECT email FROM test_invited_admins WHERE id = ? AND enabled = 1 AND verified_at IS NULL',
                    [$adminId],
                );
                if (!is_string($email) || !hash_equals(hash('sha256', strtolower(trim($email))), $emailHash)) {
                    return false;
                }
                return $this->db->executeStatement(
                    'UPDATE test_invited_admins SET password_hash = ?, verified_at = ? WHERE id = ? AND enabled = 1 AND email = ? AND verified_at IS NULL',
                    [$passwordHash, $now->format('Y-m-d H:i:s'), $adminId, $email],
                ) === 1;
            }
        };
        $tokens = new DbalAdminInvitationStore($db);
        return [new AdminInvitationCompletion($db, $tokens, new AdminInvitationOwners([$owner])), $tokens, $db];
    }
}
