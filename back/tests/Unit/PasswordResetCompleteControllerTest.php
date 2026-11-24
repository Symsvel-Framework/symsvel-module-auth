<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use SymSvel\Module\Auth\Controller\PasswordResetCompleteController;
use SymSvel\Module\Auth\Identity\ContextPasswordResetIdentity;
use SymSvel\Module\Auth\Identity\PasswordResetCompletion;
use SymSvel\Module\Auth\Identity\PasswordResetIdentity;
use SymSvel\Module\Auth\Token\PasswordResetToken;
use SymSvel\Module\Auth\Token\TokenSubject;
use SymSvel\Module\Auth\Schema\AuthTokenSchema;
use SymSvel\Module\Auth\Schema\PasswordResetSchema;
use SymSvel\Module\Auth\Token\DbalPasswordResetStore;
use SymSvel\Module\Auth\Token\DbalTokenStore;

final class PasswordResetCompleteControllerTest extends TestCase
{
    public function testInvalidPayloadAndMissingTokenDoNotExposeAccountDetails(): void
    {
        $connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $schema = new Schema();
        AuthTokenSchema::apply($schema);
        PasswordResetSchema::apply($schema);
        foreach ($schema->toSql($connection->getDatabasePlatform()) as $sql) {
            $connection->executeStatement($sql);
        }
        $controller = new PasswordResetCompleteController(new PasswordResetCompletion(
            $connection,
            new DbalPasswordResetStore($connection),
            new ContextPasswordResetIdentity([]),
            new DbalTokenStore($connection),
        ));

        $invalid = Request::create('/apibo/auth/password-reset/complete', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], '{"token":false}');
        self::assertSame(400, $controller->bo($invalid)->getStatusCode());

        $unknown = Request::create('/apibo/auth/password-reset/complete', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], json_encode([
            'token' => str_repeat('A', 43),
            'password' => 'Long-enough-password-1!',
        ], JSON_THROW_ON_ERROR));
        $response = $controller->bo($unknown);
        self::assertSame(400, $response->getStatusCode());
        self::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        self::assertSame('invalid_reset_token', json_decode((string) $response->getContent(), true)['error']['code']);
    }
    public function testValidTokenCompletesThroughHttpController(): void
    {
        $connection = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $schema = new Schema();
        AuthTokenSchema::apply($schema);
        PasswordResetSchema::apply($schema);
        foreach ($schema->toSql($connection->getDatabasePlatform()) as $sql) {
            $connection->executeStatement($sql);
        }
        $owner = new class implements PasswordResetIdentity {
            public ?string $hash = null;
            public function authContext(): string { return 'bo'; }
            public function findResetSubject(string $identifier): ?TokenSubject { return new TokenSubject('bo', 8); }
            public function recoveryEmail(TokenSubject $subject): ?string { return $subject->context === 'bo' ? 'admin@example.test' : null; }
            public function replacePassword(TokenSubject $subject, string $newPasswordHash): bool
            {
                $this->hash = $newPasswordHash;
                return true;
            }
        };
        $resets = new DbalPasswordResetStore($connection);
        $now = new \DateTimeImmutable('now', new \DateTimeZone('UTC'));
        $token = PasswordResetToken::issue('bo', $now);
        $resets->save(new TokenSubject('bo', 8), $token, $now);
        $controller = new PasswordResetCompleteController(new PasswordResetCompletion(
            $connection, $resets, new ContextPasswordResetIdentity([$owner]), new DbalTokenStore($connection),
        ));
        $request = Request::create('/apibo/auth/password-reset/complete', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], json_encode([
            'token' => $token->raw,
            'password' => 'New-long-password-1!',
        ], JSON_THROW_ON_ERROR));
        $response = $controller->bo($request);
        self::assertSame(200, $response->getStatusCode());
        self::assertSame('completed', json_decode((string) $response->getContent(), true)['status']);
        self::assertTrue(password_verify('New-long-password-1!', (string) $owner->hash));
        self::assertSame(1, (int) $connection->fetchOne('SELECT COUNT(*) FROM symsvel_auth_password_reset_tokens WHERE used_at IS NOT NULL'));
        self::assertSame(400, $controller->bo($request)->getStatusCode());
    }

}
