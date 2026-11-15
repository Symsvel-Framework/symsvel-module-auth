<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use SymSvel\Module\Auth\Controller\EmailVerificationCompleteController;
use SymSvel\Module\Auth\Identity\ContextEmailVerificationIdentity;
use SymSvel\Module\Auth\Identity\EmailVerificationCompletion;
use SymSvel\Module\Auth\Identity\EmailVerificationIdentity;
use SymSvel\Module\Auth\Schema\EmailVerificationSchema;
use SymSvel\Module\Auth\Token\DbalEmailVerificationStore;
use SymSvel\Module\Auth\Token\EmailVerificationToken;
use SymSvel\Module\Auth\Token\TokenSubject;

final class EmailVerificationCompleteControllerTest extends TestCase
{
    public function testBoCompletionAndReplayOverHttp(): void
    {
        [$controller, $store, $db] = $this->fixture();
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $token = EmailVerificationToken::issue('bo', $now);
        $store->save(new TokenSubject('bo', 7), 'admin@example.test', $token, $now);

        $first = $controller->bo(self::request(['token' => $token->raw]));
        self::assertSame(200, $first->getStatusCode());
        self::assertSame(['status' => 'completed'], json_decode($first->getContent(), true));
        self::assertTrue($first->headers->hasCacheControlDirective('no-store'));
        self::assertNotNull($db->fetchOne('SELECT verified_at FROM test_accounts WHERE id = 7'));

        $replay = $controller->bo(self::request(['token' => $token->raw]));
        self::assertSame(400, $replay->getStatusCode());
        self::assertSame('invalid_verification_token', json_decode($replay->getContent(), true)['error']['code']);
    }

    public function testMalformedPayloadAndWrongContentTypeAreRejected(): void
    {
        [$controller, $store, $db] = $this->fixture();

        $wrongType = self::request(['token' => str_repeat('a', 43)]);
        $wrongType->headers->set('Content-Type', 'text/plain');
        self::assertSame(415, $controller->bo($wrongType)->getStatusCode());

        foreach ([[], ['token' => 'invalid'], ['token' => 123], ['token' => []]] as $payload) {
            self::assertSame(400, $controller->bo(self::request($payload))->getStatusCode());
        }
        $invalidJson = Request::create('/apibo/auth/email-verification/complete', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], '{');
        self::assertSame(400, $controller->bo($invalidJson)->getStatusCode());
        self::assertSame(0, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_email_verification_tokens'));
    }

    public function testAppTokenCannotConfirmBoMailbox(): void
    {
        [$controller, $store, $db] = $this->fixture();
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $token = EmailVerificationToken::issue('app', $now);
        $store->save(new TokenSubject('app', 7), 'admin@example.test', $token, $now);

        self::assertSame(400, $controller->bo(self::request(['token' => $token->raw]))->getStatusCode());
        self::assertNull($db->fetchOne('SELECT verified_at FROM test_accounts WHERE id = 7') ?: null);
    }

    private static function request(array $payload): Request
    {
        return Request::create(
            '/apibo/auth/email-verification/complete',
            'POST',
            [],
            [],
            [],
            ['CONTENT_TYPE' => 'application/json'],
            json_encode($payload, JSON_THROW_ON_ERROR),
        );
    }

    /** @return array{EmailVerificationCompleteController, DbalEmailVerificationStore, Connection} */
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
        $db->executeStatement('CREATE TABLE test_accounts (id INTEGER PRIMARY KEY, email VARCHAR(254), enabled BOOLEAN, verified_at DATETIME NULL)');
        $db->insert('test_accounts', ['id' => 7, 'email' => 'admin@example.test', 'enabled' => true, 'verified_at' => null]);

        $owner = new class($db) implements EmailVerificationIdentity {
            public function __construct(private Connection $db) {}
            public function authContext(): string { return 'bo'; }
            public function pendingVerificationEmail(TokenSubject $subject): ?string { return null; }
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

        return [new EmailVerificationCompleteController($completion), $store, $db];
    }
}
