<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Token\AppPrincipalSecurityContributor;
use SymSvel\Module\Auth\Token\AppPrincipalSecurityData;

final class AppPrincipalSecurityDataTest extends TestCase
{
    public function testDeletesOnlyAppSubjectDataAndRollsBackContributorFailure(): void
    {
        $db = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        try {
            $tables = ['symsvel_auth_email_verification_tokens', 'symsvel_auth_password_reset_tokens', 'symsvel_auth_profile_email_changes', 'symsvel_auth_access_tokens', 'symsvel_auth_refresh_tokens', 'fixture_security'];
            foreach ($tables as $table) {
                $db->executeStatement('CREATE TABLE '.$table.' (context VARCHAR(8), principal_id INT, expires_at VARCHAR(30), revoked_at VARCHAR(30), used_at VARCHAR(30))');
                foreach ([['app', 7], ['bo', 7], ['app', 8]] as [$context, $id]) {
                    $db->insert($table, ['context' => $context, 'principal_id' => $id, 'expires_at' => '2099-01-01 00:00:00.000000']);
                }
            }
            $db->executeStatement('CREATE TABLE symsvel_auth_app_invitations (principal_id INT)');
            $db->insert('symsvel_auth_app_invitations', ['principal_id' => 7]);
            $db->insert('symsvel_auth_app_invitations', ['principal_id' => 8]);
            $contributor = new class($db) implements AppPrincipalSecurityContributor {
                public bool $fail = false;
                public function __construct(private Connection $db) {}
                public function moduleId(): string { return 'fixture-security'; }
                public function eraseAppPrincipal(int $userId): void
                {
                    $this->db->delete('fixture_security', ['context' => 'app', 'principal_id' => $userId]);
                    if ($this->fail) throw new \RuntimeException('Fixture veto.');
                }
            };
            $service = new AppPrincipalSecurityData($db, [$contributor]);
            self::assertTrue($service->hasActiveSession(7, new \DateTimeImmutable('2026-11-28T12:00:00Z')));
            $contributor->fail = true;
            try {
                $db->transactional(fn () => $service->erase(7));
                self::fail('Contributor failure must abort the transaction.');
            } catch (\RuntimeException) {
                self::assertSame(3, (int) $db->fetchOne('SELECT COUNT(*) FROM fixture_security'));
            }
            $contributor->fail = false;
            $db->transactional(fn () => $service->erase(7));
            foreach ($tables as $table) {
                self::assertSame(2, (int) $db->fetchOne('SELECT COUNT(*) FROM '.$table));
                self::assertSame(0, (int) $db->fetchOne('SELECT COUNT(*) FROM '.$table.' WHERE context = ? AND principal_id = ?', ['app', 7]));
            }
            self::assertSame(1, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_app_invitations'));
            self::assertFalse($service->hasActiveSession(7, new \DateTimeImmutable('2026-11-28T12:00:00Z')));
            $this->expectException(\LogicException::class);
            $service->erase(8);
        } finally {
            $db->close();
        }
    }
}
