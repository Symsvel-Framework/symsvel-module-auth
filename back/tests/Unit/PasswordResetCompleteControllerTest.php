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
            'password' => 'long-enough-password',
        ], JSON_THROW_ON_ERROR));
        $response = $controller->bo($unknown);
        self::assertSame(400, $response->getStatusCode());
        self::assertSame('no-store', $response->headers->get('Cache-Control'));
        self::assertSame('invalid_reset_token', json_decode((string) $response->getContent(), true)['error']['code']);
    }
}
