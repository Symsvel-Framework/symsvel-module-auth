<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Schema\AdminInvitationSchema;
use SymSvel\Module\Auth\Token\AdminInvitationToken;
use SymSvel\Module\Auth\Token\DbalAdminInvitationStore;

final class DbalAdminInvitationStoreTest extends TestCase
{
    public function testSingleUseExpiryEmailBindingAndRollback(): void
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
        $store = new DbalAdminInvitationStore($db);
        $now = new \DateTimeImmutable('2026-11-16T12:00:00+00:00');
        $token = AdminInvitationToken::issue($now);
        $store->save(17, 'Admin@Example.test', $token, $now);

        self::assertSame($token->hash, $db->fetchOne('SELECT token_hash FROM symsvel_auth_admin_invitations'));
        self::assertSame(hash('sha256', 'admin@example.test'), $db->fetchOne('SELECT email_hash FROM symsvel_auth_admin_invitations'));
        self::assertNull($store->consume('invalid', $now));

        $db->beginTransaction();
        try {
            self::assertSame([
                'adminId' => 17,
                'emailHash' => hash('sha256', 'admin@example.test'),
            ], $store->consume($token->raw, $now));
        } finally {
            $db->rollBack();
        }

        self::assertNotNull($store->consume($token->raw, $now));
        self::assertNull($store->consume($token->raw, $now));

        $expiring = AdminInvitationToken::issue($now, 1);
        $store->save(19, 'other@example.test', $expiring, $now);
        self::assertNull($store->consume($expiring->raw, $now->modify('+1 second')));
    }

    public function testRefusesInvalidSubjectOrEmail(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $db = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $store = new DbalAdminInvitationStore($db);
        $this->expectException(\InvalidArgumentException::class);
        $store->save(0, 'bad', AdminInvitationToken::issue(new \DateTimeImmutable()), new \DateTimeImmutable());
    }
}
