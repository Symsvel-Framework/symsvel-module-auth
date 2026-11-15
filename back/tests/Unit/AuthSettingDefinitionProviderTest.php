<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Unit;

use Doctrine\DBAL\DriverManager;
use Doctrine\ORM\EntityManager;
use Doctrine\ORM\ORMSetup;
use Doctrine\ORM\Tools\SchemaTool;
use Doctrine\Persistence\ManagerRegistry;
use PHPUnit\Framework\TestCase;
use SymSvel\Module\Auth\Service\AuthSettingDefinitionProvider;
use SymSvel\Module\Auth\Service\PasswordResetUrlResolver;
use SymSvel\Module\Auth\Service\EmailVerificationUrlResolver;
use SymSvel\Module\Settings\Entity\Setting;
use SymSvel\Module\Settings\Repository\SettingRepository;
use SymSvel\Module\Settings\Service\SettingKeyQualifier;
use SymSvel\Module\Settings\Service\SettingManager;
use SymSvel\Module\Settings\Service\SettingRegistry;
use SymSvel\Module\Settings\Service\SettingSecretCipher;

final class AuthSettingDefinitionProviderTest extends TestCase
{
    public function testOwnsFourNonPublicAndNonBlockingUrlSettings(): void
    {
        $registry = new SettingRegistry([]);
        $registry->registerOwned(new AuthSettingDefinitionProvider(), 'auth', new SettingKeyQualifier());
        $definitions = $registry->all();
        self::assertCount(4, $definitions);
        $byKey = [];
        foreach ($definitions as $definition) {
            $byKey[$definition->key] = $definition;
        }
        foreach (['auth.bo_reset_url', 'auth.app_reset_url', 'auth.bo_verify_email_url', 'auth.app_verify_email_url'] as $key) {
            self::assertArrayHasKey($key, $byKey);
            self::assertSame('url', $byKey[$key]->type);
            self::assertFalse($byKey[$key]->public);
            self::assertFalse($byKey[$key]->blocking);
            self::assertFalse($byKey[$key]->required);
        }
    }

    public function testResolverRejectsUnconfiguredAndUnsafeUrls(): void
    {
        $settings = $this->settings();
        $resolver = new PasswordResetUrlResolver($settings);

        foreach (['bo', 'app'] as $context) {
            try {
                $resolver->forContext($context);
                self::fail('An unconfigured URL must be refused.');
            } catch (\LogicException) {
            }
        }
        $settings->set('auth.bo_reset_url', 'http://bo.example.test/reset');
        $settings->flush();
        $this->expectException(\LogicException::class);
        $resolver->forContext('bo');
    }

    public function testResolverUsesTrustedConfiguredUrlPerContext(): void
    {
        $settings = $this->settings();
        $settings->set('auth.bo_reset_url', 'https://bo.example.test/reset');
        $settings->set('auth.app_reset_url', 'https://app.example.test/reset');
        $settings->flush();
        $resolver = new PasswordResetUrlResolver($settings);
        self::assertSame('https://bo.example.test/reset', $resolver->forContext('bo'));
        self::assertSame('https://app.example.test/reset', $resolver->forContext('app'));
        $this->expectException(\InvalidArgumentException::class);
        $resolver->forContext('invalid');
    }

    public function testVerificationUrlResolverUsesTrustedContextSettings(): void
    {
        $settings = $this->settings();
        $resolver = new EmailVerificationUrlResolver($settings);
        foreach (['bo', 'app'] as $context) {
            try {
                $resolver->forContext($context);
                self::fail('Missing URL must be rejected.');
            } catch (\LogicException) {
            }
        }

        $settings->set('auth.bo_verify_email_url', 'https://bo.example.test/confirm-email');
        $settings->set('auth.app_verify_email_url', 'https://app.example.test/confirm-email');
        $settings->flush();
        self::assertSame('https://bo.example.test/confirm-email', $resolver->forContext('bo'));
        self::assertSame('https://app.example.test/confirm-email', $resolver->forContext('app'));

        $settings->set('auth.bo_verify_email_url', 'https://bo.example.test/confirm-email?to=evil');
        $settings->flush();
        $this->expectException(\LogicException::class);
        $resolver->forContext('bo');
    }

    private function settings(): SettingManager
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite is required.');
        }
        $registry = new SettingRegistry([]);
        $registry->registerOwned(new AuthSettingDefinitionProvider(), 'auth', new SettingKeyQualifier());
        $config = ORMSetup::createAttributeMetadataConfiguration(
            paths: [dirname((new \ReflectionClass(Setting::class))->getFileName())],
            isDevMode: true,
        );
        $config->enableNativeLazyObjects(true);
        $em = new EntityManager(DriverManager::getConnection(['driver' => 'pdo_sqlite', 'memory' => true]), $config);
        (new SchemaTool($em))->createSchema([$em->getClassMetadata(Setting::class)]);
        $doctrineRegistry = $this->createMock(ManagerRegistry::class);
        $doctrineRegistry->method('getManagerForClass')->with(Setting::class)->willReturn($em);
        return new SettingManager(
            $registry, new SettingRepository($doctrineRegistry), $em, new SettingSecretCipher('unit-test-secret'),
        );
    }
}
