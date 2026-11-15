<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Schema\EmailVerificationSchema;
use SymSvel\Module\Auth\Token\DbalEmailVerificationStore;
use SymSvel\Module\Auth\Token\EmailVerificationToken;
use SymSvel\Module\Auth\Token\TokenSubject;

final class DbalEmailVerificationStoreTest extends TestCase
{
    public function testTokenIsSingleUseBoundToContextAndMailbox(): void
    {
        [$store, $db] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        $subject = new TokenSubject('bo', 17);
        $token = EmailVerificationToken::issue('bo', $now);
        $store->save($subject, 'Admin@Example.test', $token, $now);

        self::assertSame(1, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_email_verification_tokens'));
        self::assertSame($token->hash, $db->fetchOne('SELECT token_hash FROM symsvel_auth_email_verification_tokens'));
        self::assertSame(hash('sha256', 'admin@example.test'), $db->fetchOne('SELECT email_hash FROM symsvel_auth_email_verification_tokens'));
        self::assertNull($store->consume('app', $token->raw, $now));

        $result = $store->consume('bo', $token->raw, $now);
        self::assertNotNull($result);
        self::assertEquals($subject, $result['subject']);
        self::assertSame(hash('sha256', 'admin@example.test'), $result['emailHash']);
        self::assertNull($store->consume('bo', $token->raw, $now));
        self::assertNull($store->consume('bo', 'invalid', $now));
    }

    public function testExpirationAndRollbackDoNotGrantVerification(): void
    {
        [$store, $db] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        $expired = EmailVerificationToken::issue('app', $now, 1);
        $store->save(new TokenSubject('app', 42), 'user@example.test', $expired, $now);
        self::assertNull($store->consume('app', $expired->raw, $now->modify('+1 second')));

        $token = EmailVerificationToken::issue('app', $now);
        $store->save(new TokenSubject('app', 42), 'user@example.test', $token, $now);
        $db->beginTransaction();
        try {
            self::assertNotNull($store->consume('app', $token->raw, $now));
        } finally {
            $db->rollBack();
        }
        self::assertNotNull($store->consume('app', $token->raw, $now));
    }

    public function testInvalidEmailOrContextIsRejectedBeforePersistence(): void
    {
        [$store, $db] = $this->fixture();
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        try {
            $store->save(new TokenSubject('bo', 1), 'invalid', EmailVerificationToken::issue('bo', $now), $now);
            self::fail('An invalid email must not be stored.');
        } catch (\InvalidArgumentException) {
        }
        try {
            $store->save(new TokenSubject('app', 1), 'user@example.test', EmailVerificationToken::issue('bo', $now), $now);
            self::fail('A mismatched context must not be stored.');
        } catch (\InvalidArgumentException) {
        }
        self::assertSame(0, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_email_verification_tokens'));
    }

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

        return [new DbalEmailVerificationStore($db), $db];
    }
}
