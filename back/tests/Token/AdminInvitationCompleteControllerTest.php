<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use SymSvel\Module\Auth\Controller\AdminInvitationCompleteController;
use SymSvel\Module\Auth\Identity\AdminInvitationCompletion;
use SymSvel\Module\Auth\Identity\AdminInvitationIdentity;
use SymSvel\Module\Auth\Identity\AdminInvitationOwners;
use SymSvel\Module\Auth\Schema\AdminInvitationSchema;
use SymSvel\Module\Auth\Token\AdminInvitationToken;
use SymSvel\Module\Auth\Token\DbalAdminInvitationStore;

final class AdminInvitationCompleteControllerTest extends TestCase
{
    public function testCompletesInvitationOnlyOnceAndDisablesCaching(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite required.');
        }
        $db = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $schema = new Schema();
        AdminInvitationSchema::apply($schema);
        foreach ($schema->toSql($db->getDatabasePlatform()) as $sql) {
            $db->executeStatement($sql);
        }
        $db->executeStatement('CREATE TABLE invited (id INTEGER PRIMARY KEY, email VARCHAR(254), password_hash VARCHAR(255), verified_at DATETIME NULL)');
        $db->insert('invited', ['id' => 7, 'email' => 'new@example.test', 'password_hash' => 'pending', 'verified_at' => null]);
        $owner = new class($db) implements AdminInvitationIdentity {
            public function __construct(private Connection $db) {}
            public function activateInvitation(int $adminId, string $emailHash, string $passwordHash, \DateTimeImmutable $now): bool
            {
                $email = $this->db->fetchOne('SELECT email FROM invited WHERE id = ? AND verified_at IS NULL', [$adminId]);
                if (!is_string($email) || !hash_equals(hash('sha256', strtolower($email)), $emailHash)) {
                    return false;
                }
                return $this->db->executeStatement(
                    'UPDATE invited SET password_hash = ?, verified_at = ? WHERE id = ? AND verified_at IS NULL',
                    [$passwordHash, $now->format('Y-m-d H:i:s'), $adminId],
                ) === 1;
            }
        };
        $store = new DbalAdminInvitationStore($db);
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $token = AdminInvitationToken::issue($now);
        $store->save(7, 'new@example.test', $token, $now);
        $controller = new AdminInvitationCompleteController(new AdminInvitationCompletion($db, $store, new AdminInvitationOwners([$owner])));
        $body = json_encode(['token' => $token->raw, 'password' => 'strong-new-password'], JSON_THROW_ON_ERROR);
        $request = Request::create('/apibo/auth/invitation/complete', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], $body);
        $response = $controller->bo($request);
        self::assertSame(200, $response->getStatusCode());
        self::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        self::assertTrue(password_verify('strong-new-password', (string) $db->fetchOne('SELECT password_hash FROM invited WHERE id = 7')));
        self::assertSame(400, $controller->bo($request)->getStatusCode());
        self::assertSame(415, $controller->bo(Request::create('/apibo/auth/invitation/complete', 'POST'))->getStatusCode());
        self::assertSame(400, $controller->bo(Request::create('/apibo/auth/invitation/complete', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], '{"token":false}'))->getStatusCode());
    }
}
