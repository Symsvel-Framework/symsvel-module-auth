<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Argument\TaggedIteratorArgument;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;
use SymSvel\Module\Auth\AuthBundle;
use SymSvel\Module\Auth\Controller\EmailVerificationCompleteController;
use SymSvel\Module\Auth\Controller\AdminInvitationCompleteController;
use SymSvel\Module\Auth\Identity\PasswordLogin;
use SymSvel\Module\Auth\Identity\PasswordResetLimiter;
use SymSvel\Module\Auth\Identity\PasswordResetDispatch;
use SymSvel\Module\Auth\Identity\ContextEmailVerificationIdentity;
use SymSvel\Module\Auth\Identity\EmailVerificationCompletion;
use SymSvel\Module\Auth\Identity\AdminInvitationCompletion;
use SymSvel\Module\Auth\Identity\AdminInvitationDispatch;
use SymSvel\Module\Auth\Identity\AdminInvitationOwners;
use SymSvel\Module\Auth\Identity\EmailVerificationDispatch;
use SymSvel\Module\Auth\Service\AuthSettingDefinitionProvider;
use SymSvel\Module\Auth\Service\PasswordResetUrlResolver;
use SymSvel\Module\Auth\Service\EmailVerificationUrlResolver;
use SymSvel\Module\Auth\Identity\ContextIdentityProvider;
use SymSvel\Module\Auth\Identity\PasswordPrincipal;
use SymSvel\Module\Auth\Identity\PrincipalStatus;
use SymSvel\Module\Auth\Identity\AuthenticatedTokenResolver;
use SymSvel\Module\Auth\Token\AccessTokenLookup;
use SymSvel\Module\Auth\Token\AccessTokenVerifier;
use SymSvel\Module\Auth\Token\DbalTokenStore;
use SymSvel\Module\Auth\Token\DbalEmailVerificationStore;
use SymSvel\Module\Auth\Token\DbalAdminInvitationStore;
use SymSvel\Module\Auth\Token\TokenIssuer;
use SymSvel\Module\Auth\Token\TokenLogout;
use SymSvel\Module\Auth\Token\TokenRotation;
use SymSvel\Module\Auth\Token\TokenSessionRevoker;
use SymSvel\Module\Auth\Token\TokenStore;

final class AuthBundleServicesTest extends TestCase
{
    public function testBundleRegistersSharedDbalStoreAndAllTokenServices(): void
    {
        $builder = new ContainerBuilder();
        // The bundle does not use the configurator: only ContainerBuilder is
        // needed to inspect the Symfony service definitions.
        $configurator = (new \ReflectionClass(ContainerConfigurator::class))->newInstanceWithoutConstructor();
        (new AuthBundle())->loadExtension([], $configurator, $builder);

        self::assertTrue($builder->hasDefinition(AdminInvitationCompleteController::class));
        self::assertArrayHasKey('controller.service_arguments', $builder->getDefinition(AdminInvitationCompleteController::class)->getTags());
        self::assertTrue($builder->hasDefinition(EmailVerificationCompleteController::class));
        self::assertArrayHasKey('controller.service_arguments', $builder->getDefinition(EmailVerificationCompleteController::class)->getTags());

        self::assertTrue($builder->hasDefinition(ContextEmailVerificationIdentity::class));
        $emailOwners = $builder->getDefinition(ContextEmailVerificationIdentity::class)->getArgument('$providers');
        self::assertInstanceOf(TaggedIteratorArgument::class, $emailOwners);
        self::assertSame('symsvel.auth.email_verification_identity', $emailOwners->getTag());
        self::assertTrue($builder->hasDefinition(AdminInvitationCompletion::class));
        self::assertTrue($builder->getDefinition(AdminInvitationCompletion::class)->isAutowired());
        $invitationOwners = $builder->getDefinition(AdminInvitationOwners::class)->getArgument('$owners');
        self::assertInstanceOf(TaggedIteratorArgument::class, $invitationOwners);
        self::assertSame('symsvel.auth.admin_invitation_identity', $invitationOwners->getTag());
        self::assertTrue($builder->hasDefinition(EmailVerificationCompletion::class));
        self::assertTrue($builder->getDefinition(EmailVerificationCompletion::class)->isAutowired());

        self::assertTrue($builder->hasDefinition(AuthSettingDefinitionProvider::class));
        self::assertArrayHasKey('symsvel.settings.definition_provider', $builder->getDefinition(AuthSettingDefinitionProvider::class)->getTags());
        self::assertTrue($builder->hasDefinition(PasswordResetUrlResolver::class));
        self::assertTrue($builder->getDefinition(PasswordResetUrlResolver::class)->isAutowired());
        self::assertTrue($builder->hasDefinition(EmailVerificationUrlResolver::class));
        self::assertTrue($builder->getDefinition(EmailVerificationUrlResolver::class)->isAutowired());

        self::assertSame(ContextIdentityProvider::class, (string) $builder->getAlias(PasswordPrincipal::class));
        self::assertSame(ContextIdentityProvider::class, (string) $builder->getAlias(PrincipalStatus::class));
        self::assertTrue($builder->getDefinition(ContextIdentityProvider::class)->isAutowired());
        $providers = $builder->getDefinition(ContextIdentityProvider::class)->getArgument('$providers');
        self::assertInstanceOf(TaggedIteratorArgument::class, $providers);
        self::assertSame('symsvel.auth.identity_provider', $providers->getTag());

        self::assertSame(DbalTokenStore::class, (string) $builder->getAlias(TokenStore::class));
        self::assertSame(DbalTokenStore::class, (string) $builder->getAlias(AccessTokenLookup::class));

        $confirmationConnection = $builder->getDefinition(DbalEmailVerificationStore::class)->getArgument('$connection');
        self::assertInstanceOf(Reference::class, $confirmationConnection);
        self::assertSame('doctrine.dbal.default_connection', (string) $confirmationConnection);

        $invitationConnection = $builder->getDefinition(DbalAdminInvitationStore::class)->getArgument('$connection');
        self::assertInstanceOf(Reference::class, $invitationConnection);
        self::assertSame('doctrine.dbal.default_connection', (string) $invitationConnection);

        $connection = $builder->getDefinition(DbalTokenStore::class)->getArgument('$connection');
        self::assertInstanceOf(Reference::class, $connection);
        self::assertSame('doctrine.dbal.default_connection', (string) $connection);

        foreach ([
            PasswordLogin::class,
            PasswordResetLimiter::class,
            PasswordResetDispatch::class,
            EmailVerificationDispatch::class,
            AdminInvitationDispatch::class,
            AuthenticatedTokenResolver::class,
            TokenIssuer::class,
            TokenRotation::class,
            TokenLogout::class,
            TokenSessionRevoker::class,
            AccessTokenVerifier::class,
        ] as $service) {
            self::assertTrue($builder->hasDefinition($service), $service.' must be registered.');
            self::assertTrue($builder->getDefinition($service)->isAutowired());
        }
    }
}
