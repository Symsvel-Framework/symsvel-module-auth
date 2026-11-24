<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Identity\AppInvitationCompletion;
use SymSvel\Module\Auth\Identity\AppInvitationIdentity;
use SymSvel\Module\Auth\Identity\AppInvitationOwners;
use SymSvel\Module\Auth\Schema\AppInvitationSchema;
use SymSvel\Module\Auth\Token\AppInvitationToken;
use SymSvel\Module\Auth\Token\DbalAppInvitationStore;

final class AppInvitationCompletionTest extends TestCase
{
    public function testAppInvitationIsBoundToCurrentMailboxAndCanBeUsedOnce(): void
    {
        if (!extension_loaded('pdo_sqlite')) self::markTestSkipped('pdo_sqlite required.');
        $db = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $schema = new Schema();
        AppInvitationSchema::apply($schema);
        foreach ($schema->toSql($db->getDatabasePlatform()) as $sql) $db->executeStatement($sql);
        $db->executeStatement('CREATE TABLE invited_users (id INTEGER PRIMARY KEY, email VARCHAR(254), enabled BOOLEAN, verified_at DATETIME NULL, password_hash VARCHAR(255))');
        $db->insert('invited_users', ['id' => 7, 'email' => 'user@example.test', 'enabled' => true, 'verified_at' => null, 'password_hash' => 'pending']);

        $owner = new class($db) implements AppInvitationIdentity {
            public function __construct(private \Doctrine\DBAL\Connection $db) {}
            public function activateInvitation(int $userId, string $emailHash, string $passwordHash, \DateTimeImmutable $now): bool
            {
                $email = $this->db->fetchOne('SELECT email FROM invited_users WHERE id = ? AND enabled = 1 AND verified_at IS NULL', [$userId]);
                if (!is_string($email) || !hash_equals(hash('sha256', $email), $emailHash)) return false;
                return $this->db->executeStatement('UPDATE invited_users SET verified_at = ?, password_hash = ? WHERE id = ? AND email = ? AND verified_at IS NULL',
                    [$now->format('Y-m-d H:i:s'), $passwordHash, $userId, $email]) === 1;
            }
        };
        $tokens = new DbalAppInvitationStore($db);
        $completion = new AppInvitationCompletion($db, $tokens, new AppInvitationOwners([$owner]));
        $now = new \DateTimeImmutable('2026-11-16T12:00:00+00:00');
        $token = AppInvitationToken::issue($now);
        $tokens->save(7, 'user@example.test', $token, $now);
        $db->update('invited_users', ['email' => 'other@example.test'], ['id' => 7]);
        self::assertFalse($completion->complete($token->raw, 'Password-with-length-1!', $now));
        self::assertNull($db->fetchOne('SELECT used_at FROM symsvel_auth_app_invitations WHERE token_hash = ?', [$token->hash]) ?: null);
        $db->update('invited_users', ['email' => 'user@example.test'], ['id' => 7]);
        self::assertTrue($completion->complete($token->raw, 'Password-with-length-1!', $now));
        self::assertFalse($completion->complete($token->raw, 'Password-with-length-1!', $now));
        self::assertTrue(password_verify('Password-with-length-1!', (string) $db->fetchOne('SELECT password_hash FROM invited_users WHERE id = 7')));
        self::assertNotNull($db->fetchOne('SELECT verified_at FROM invited_users WHERE id = 7'));
    }
}

