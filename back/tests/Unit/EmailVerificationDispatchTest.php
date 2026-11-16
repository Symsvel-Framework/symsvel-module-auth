<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use Doctrine\DBAL\DriverManager;
use Doctrine\DBAL\Schema\Schema;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use Doctrine\Persistence\ManagerRegistry;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\RawMessage;
use SymSvel\Module\Auth\Identity\ContextPasswordResetIdentity;
use SymSvel\Module\Auth\Identity\EmailVerificationDispatch;
use SymSvel\Module\Auth\Identity\EmailVerificationIdentity;
use SymSvel\Module\Auth\Identity\ContextEmailVerificationIdentity;
use SymSvel\Module\Auth\Identity\PasswordResetLimiter;
use SymSvel\Module\Auth\Identity\PasswordResetIdentity;
use SymSvel\Module\Auth\Mail\AuthMailTemplateProvider;
use SymSvel\Module\Auth\Schema\EmailVerificationSchema;
use SymSvel\Module\Auth\Service\AuthSettingDefinitionProvider;
use SymSvel\Module\Auth\Service\EmailVerificationUrlResolver;
use SymSvel\Module\Auth\Schema\PasswordResetLimitSchema;
use SymSvel\Module\Auth\Token\DbalEmailVerificationStore;
use SymSvel\Module\Auth\Token\TokenSubject;
use SymSvel\Module\Mails\Mail\ConfiguredMailSender;
use SymSvel\Module\Mails\Mail\MailSender;
use SymSvel\Module\Mails\Mail\MailTemplateRegistry;
use SymSvel\Module\Mails\Mail\RegisteredMailRenderer;
use SymSvel\Module\Mails\Service\MailsSettingDefinitionProvider;
use SymSvel\Module\Settings\Entity\Setting;
use SymSvel\Module\Settings\Repository\SettingRepository;
use SymSvel\Module\Settings\Service\SettingKeyQualifier;
use SymSvel\Module\Settings\Service\SettingManager;
use SymSvel\Module\Settings\Service\SettingRegistry;
use SymSvel\Module\Settings\Service\SettingSecretCipher;
use Twig\Environment;
use Twig\Loader\FilesystemLoader;

final class EmailVerificationDispatchTest extends TestCase
{
    public function testSendsToOwnerPendingEmailAndStoresOnlyHashes(): void
    {
        [$dispatch, $db, $mailer] = $this->fixture(true);
        $message = null;
        $mailer->expects(self::once())->method('send')->willReturnCallback(
            static function (RawMessage $mail) use (&$message): void { $message = $mail; },
        );
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        self::assertTrue($dispatch->dispatch('bo', 'known', 'fr', '192.0.2.10', $now));
        self::assertInstanceOf(Email::class, $message);
        self::assertSame('pending@example.test', $message->getTo()[0]->getAddress());
        self::assertStringContainsString('https://bo.example.test/confirm-email?token=', (string) $message->getTextBody());
        self::assertSame(1, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_email_verification_tokens'));
        self::assertSame(hash('sha256', 'pending@example.test'), $db->fetchOne(
            'SELECT email_hash FROM symsvel_auth_email_verification_tokens',
        ));
        self::assertSame(
            2, (int) $db->fetchOne("SELECT COUNT(*) FROM symsvel_auth_reset_limits WHERE scope LIKE 'verify_%'"),
        );
    }

    public function testUnknownIdentityConsumesQuotaButNeverSends(): void
    {
        [$dispatch, $db, $mailer] = $this->fixture(true);
        $mailer->expects(self::never())->method('send');
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        self::assertFalse($dispatch->dispatch('bo', 'missing', 'fr', '192.0.2.10', $now));
        self::assertSame(0, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_email_verification_tokens'));
        self::assertSame(2, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_reset_limits'));
    }

    public function testVerificationQuotaBlocksRepeatedDelivery(): void
    {
        [$dispatch, $db, $mailer] = $this->fixture(true);
        $mailer->expects(self::once())->method('send');
        $now = new \DateTimeImmutable('2026-11-15T12:00:00+00:00');
        self::assertTrue($dispatch->dispatch('bo', 'known', 'en', '192.0.2.10', $now));
        self::assertFalse($dispatch->dispatch('bo', 'known', 'en', '192.0.2.11', $now));
        self::assertSame(1, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_email_verification_tokens'));
    }

    public function testMissingSetupDomainPreventsSendingOrQuotaReservation(): void
    {
        [$dispatch, $db, $mailer] = $this->fixture(true);
        $mailer->expects(self::never())->method('send');
        try {
            $dispatch->dispatch('app', 'known', 'fr', '192.0.2.10', new \DateTimeImmutable());
            self::fail('Missing Setup domain should be rejected.');
        } catch (\LogicException) {
            self::assertSame(0, (int) $db->fetchOne('SELECT COUNT(*) FROM symsvel_auth_reset_limits'));
        }
    }

    /** @return array{EmailVerificationDispatch, \Doctrine\DBAL\Connection, MailerInterface} */
    private function fixture(bool $active): array
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $db = DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]);
        $schema = new Schema();
        EmailVerificationSchema::apply($schema);
        PasswordResetLimitSchema::apply($schema);
        foreach ($schema->toSql($db->getDatabasePlatform()) as $sql) {
            $db->executeStatement($sql);
        }

        $owner = new class($active) implements PasswordResetIdentity, EmailVerificationIdentity {
            public function __construct(private bool $active) {}
            public function authContext(): string { return 'bo'; }
            public function findResetSubject(string $identifier): ?TokenSubject
            {
                return $this->active && $identifier === 'known' ? new TokenSubject('bo', 7) : null;
            }
            public function recoveryEmail(TokenSubject $subject): ?string
            {
                return $this->active && $subject->context === 'bo' && $subject->id === 7
                    ? 'verified@example.test' : null;
            }
            public function pendingVerificationEmail(TokenSubject $subject): ?string
            {
                return $this->active && $subject->context === 'bo' && $subject->id === 7
                    ? 'pending@example.test' : null;
            }
            public function confirmEmail(TokenSubject $subject, string $emailHash, \DateTimeImmutable $now): bool
            {
                return false;
            }
            public function replacePassword(TokenSubject $subject, string $newPasswordHash): bool { return false; }
        };

        $registry = new SettingRegistry([]);
        $registry->registerOwned(new MailsSettingDefinitionProvider(), 'mails', new SettingKeyQualifier());
        $registry->registerOwned(new AuthSettingDefinitionProvider(), 'auth', new SettingKeyQualifier());
        $config = ORMSetup::createAttributeMetadataConfiguration(
            paths: [dirname((new \ReflectionClass(Setting::class))->getFileName())],
            isDevMode: true,
        );
        $config->enableNativeLazyObjects(true);
        $em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($em))->createSchema([$em->getClassMetadata(Setting::class)]);
        foreach (['mails.sender_email' => 'sender@example.test', 'auth.bo_verify_email_url' => 'https://bo.example.test/confirm-email'] as $key => $value) {
            $setting = new Setting($key);
            $setting->setValue($value);
            $em->persist($setting);
        }
        $em->flush();
        $em->clear();
        $doctrineRegistry = $this->createMock(ManagerRegistry::class);
        $doctrineRegistry->method('getManagerForClass')->with(Setting::class)->willReturn($em);
        $settings = new SettingManager(
            $registry, new SettingRepository($doctrineRegistry), $em, new SettingSecretCipher('unit-test-secret'),
        );
        $mailer = $this->createMock(MailerInterface::class);
        $twigLoader = new FilesystemLoader();
        $twigLoader->addPath(__DIR__.'/../../templates', 'Auth');
        $renderer = new RegisteredMailRenderer(
            new MailTemplateRegistry([new AuthMailTemplateProvider()]),
            new Environment($twigLoader, ['autoescape' => 'name']),
        );

        return [
            new EmailVerificationDispatch(
                new PasswordResetLimiter($db, 'test-secret-at-least-16-characters'),
                new EmailVerificationUrlResolver($settings, sys_get_temp_dir().'/symsvel-auth-missing-project/backend'),
                new ContextPasswordResetIdentity([$owner]),
                new ContextEmailVerificationIdentity([$owner]), new DbalEmailVerificationStore($db),
                $renderer, new ConfiguredMailSender(new MailSender($mailer), $settings),
            ),
            $db,
            $mailer,
        ];
    }
}
