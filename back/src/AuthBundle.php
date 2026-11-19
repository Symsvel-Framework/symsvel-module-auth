<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Argument\TaggedIteratorArgument;
use SymSvel\Module\Auth\Controller\BoLoginController;
use SymSvel\Module\Auth\Browser\TrustedBoOrigin;
use SymSvel\Module\Auth\Controller\BoBrowserSessionController;
use SymSvel\Module\Auth\Controller\AppAuthenticationController;
use SymSvel\Module\Auth\Controller\AppEmailVerificationController;
use SymSvel\Module\Auth\Controller\AppPasswordResetController;
use SymSvel\Module\Auth\Controller\BoRefreshController;
use SymSvel\Module\Auth\Controller\BoLogoutController;
use SymSvel\Module\Auth\Controller\BoSessionController;
use SymSvel\Module\Auth\Controller\PasswordResetCompleteController;
use SymSvel\Module\Auth\Controller\EmailVerificationCompleteController;
use SymSvel\Module\Auth\Controller\ProfileEmailChangeCompleteController;
use SymSvel\Module\Auth\Controller\AdminInvitationCompleteController;
use SymSvel\Module\Auth\Controller\AppInvitationCompleteController;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use SymSvel\Module\Auth\Identity\AuthenticatedTokenResolver;
use SymSvel\Module\Auth\Identity\ContextIdentityProvider;
use SymSvel\Module\Auth\Identity\ContextPasswordResetIdentity;
use SymSvel\Module\Auth\Identity\ContextEmailVerificationIdentity;
use SymSvel\Module\Auth\Identity\EmailVerificationCompletion;
use SymSvel\Module\Auth\Identity\ContextProfileEmailOwners;
use SymSvel\Module\Auth\Identity\ProfileEmailChangeCompletion;
use SymSvel\Module\Auth\Identity\ProfileEmailChangeDispatch;
use SymSvel\Module\Auth\Identity\AdminInvitationOwners;
use SymSvel\Module\Auth\Identity\AppInvitationOwners;
use SymSvel\Module\Auth\Identity\AdminInvitationCompletion;
use SymSvel\Module\Auth\Identity\AdminInvitationDispatch;
use SymSvel\Module\Auth\Identity\AppInvitationCompletion;
use SymSvel\Module\Auth\Identity\AppInvitationDispatch;
use SymSvel\Module\Auth\Identity\EmailVerificationDispatch;
use SymSvel\Module\Auth\Identity\PasswordPrincipal;
use SymSvel\Module\Auth\Identity\PrincipalStatus;
use SymSvel\Module\Auth\Identity\PasswordLogin;
use SymSvel\Module\Auth\Identity\PasswordResetCompletion;
use SymSvel\Module\Auth\Identity\PasswordResetDispatch;
use SymSvel\Module\Auth\Identity\PasswordResetLimiter;
use SymSvel\Module\Auth\Mail\AuthMailTemplateProvider;
use SymSvel\Module\Auth\Service\AuthSettingDefinitionProvider;
use SymSvel\Module\Auth\Service\AuthPageUrls;
use SymSvel\Module\Auth\Service\PasswordResetUrlResolver;
use SymSvel\Module\Auth\Service\EmailVerificationUrlResolver;
use SymSvel\Module\Auth\Service\AdminInvitationUrlResolver;
use SymSvel\Module\Auth\Service\AppInvitationUrlResolver;
use SymSvel\Module\Auth\Token\AccessTokenLookup;
use SymSvel\Module\Auth\Token\BoSessionLogout;
use SymSvel\Module\Auth\Token\ContextSessionLogout;
use SymSvel\Module\Auth\Token\AccessTokenVerifier;
use SymSvel\Module\Auth\Token\DbalTokenStore;
use SymSvel\Module\Auth\Token\DbalPasswordResetStore;
use SymSvel\Module\Auth\Token\DbalEmailVerificationStore;
use SymSvel\Module\Auth\Token\DbalProfileEmailChangeStore;
use SymSvel\Module\Auth\Token\DbalAdminInvitationStore;
use SymSvel\Module\Auth\Token\DbalAppInvitationStore;
use SymSvel\Module\Auth\Token\RefreshTokenGuard;
use SymSvel\Module\Auth\Token\TokenFactory;
use SymSvel\Module\Auth\Token\TokenIssuer;
use SymSvel\Module\Auth\Token\TokenLogout;
use SymSvel\Module\Auth\Token\TokenRotation;
use SymSvel\Module\Auth\Token\TokenSessionRevoker;
use SymSvel\Module\Auth\Token\TokenStore;

final class AuthBundle extends AbstractBundle
{
    public function prependExtension(ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        // Auth owns its transactional templates; expose them under @Auth.
        $container->extension('twig', [
            'paths' => [dirname(__DIR__).'/templates' => 'Auth'],
        ]);
    }

    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $builder->register(AuthMailTemplateProvider::class, AuthMailTemplateProvider::class)
            ->addTag('symsvel.mails.template_provider');
        $builder->register(AuthSettingDefinitionProvider::class, AuthSettingDefinitionProvider::class)
            ->addTag('symsvel.settings.definition_provider');
        $builder->register(AuthPageUrls::class, AuthPageUrls::class)
            ->setAutowired(true);
        $builder->register(PasswordResetUrlResolver::class, PasswordResetUrlResolver::class)
            ->setAutowired(true);
        $builder->register(EmailVerificationUrlResolver::class, EmailVerificationUrlResolver::class)
            ->setAutowired(true);
        $builder->register(AdminInvitationUrlResolver::class, AdminInvitationUrlResolver::class)
            ->setAutowired(true);
        $builder->register(AppInvitationUrlResolver::class, AppInvitationUrlResolver::class)
            ->setAutowired(true);

        // Reuse the same DBAL connection as the host application.
        $builder->register(DbalTokenStore::class, DbalTokenStore::class)
            ->setArgument('$connection', new Reference('doctrine.dbal.default_connection'));

        $builder->register(DbalPasswordResetStore::class, DbalPasswordResetStore::class)
            ->setArgument('$connection', new Reference('doctrine.dbal.default_connection'));
        $builder->register(DbalEmailVerificationStore::class, DbalEmailVerificationStore::class)
            ->setArgument('$connection', new Reference('doctrine.dbal.default_connection'));
        $builder->register(DbalProfileEmailChangeStore::class, DbalProfileEmailChangeStore::class)
            ->setArgument('$db', new Reference('doctrine.dbal.default_connection'));
        $builder->register(DbalAdminInvitationStore::class, DbalAdminInvitationStore::class)
            ->setArgument('$connection', new Reference('doctrine.dbal.default_connection'));
        $builder->register(DbalAppInvitationStore::class, DbalAppInvitationStore::class)
            ->setArgument('$connection', new Reference('doctrine.dbal.default_connection'));

        $builder->setAlias(TokenStore::class, DbalTokenStore::class);
        $builder->setAlias(AccessTokenLookup::class, DbalTokenStore::class);

        $builder->register(BoSessionLogout::class, BoSessionLogout::class)
            ->setArgument('$connection', new Reference('doctrine.dbal.default_connection'));
        $builder->register(ContextSessionLogout::class, ContextSessionLogout::class)
            ->setArgument('$connection', new Reference('doctrine.dbal.default_connection'));

        $builder->register(ContextIdentityProvider::class, ContextIdentityProvider::class)
            ->setAutowired(true)
            ->setArgument('$providers', new TaggedIteratorArgument('symsvel.auth.identity_provider'));
        $builder->register(ContextPasswordResetIdentity::class, ContextPasswordResetIdentity::class)
            ->setArgument('$providers', new TaggedIteratorArgument('symsvel.auth.password_reset_identity'));
        $builder->register(ContextEmailVerificationIdentity::class, ContextEmailVerificationIdentity::class)
            ->setArgument('$providers', new TaggedIteratorArgument('symsvel.auth.email_verification_identity'));
        $builder->register(ContextProfileEmailOwners::class, ContextProfileEmailOwners::class)
            ->setArgument('$providers', new TaggedIteratorArgument('symsvel.auth.profile_email_owner'));
        $builder->register(AdminInvitationCompletion::class, AdminInvitationCompletion::class)
            ->setAutowired(true)
            ->setArgument('$connection', new Reference('doctrine.dbal.default_connection'));
        $builder->register(AdminInvitationOwners::class, AdminInvitationOwners::class)
            ->setArgument('$owners', new TaggedIteratorArgument('symsvel.auth.admin_invitation_identity'));
        $builder->register(AppInvitationOwners::class, AppInvitationOwners::class)
            ->setArgument('$owners', new TaggedIteratorArgument('symsvel.auth.app_invitation_identity'));
        $builder->register(AppInvitationCompletion::class, AppInvitationCompletion::class)
            ->setAutowired(true)
            ->setArgument('$connection', new Reference('doctrine.dbal.default_connection'));
        $builder->register(EmailVerificationCompletion::class, EmailVerificationCompletion::class)
            ->setAutowired(true)
            ->setArgument('$connection', new Reference('doctrine.dbal.default_connection'));
        $builder->register(PasswordResetLimiter::class, PasswordResetLimiter::class)
            ->setAutowired(true)
            ->setArgument('$connection', new Reference('doctrine.dbal.default_connection'));
        $builder->register(PasswordResetCompletion::class, PasswordResetCompletion::class)
            ->setAutowired(true)
            ->setArgument('$connection', new Reference('doctrine.dbal.default_connection'));
        $builder->setAlias(PasswordPrincipal::class, ContextIdentityProvider::class);
        $builder->setAlias(PrincipalStatus::class, ContextIdentityProvider::class);

        $builder->register(TrustedBoOrigin::class, TrustedBoOrigin::class)->setAutowired(true);

        foreach ([ProfileEmailChangeCompleteController::class, BoBrowserSessionController::class, BoLoginController::class, AppAuthenticationController::class, AppEmailVerificationController::class, AppPasswordResetController::class, BoSessionController::class, BoLogoutController::class, BoRefreshController::class, PasswordResetCompleteController::class, EmailVerificationCompleteController::class, AdminInvitationCompleteController::class, AppInvitationCompleteController::class] as $controller) {
            $builder->register($controller, $controller)
                ->setAutowired(true)
                ->addTag('controller.service_arguments');
        }

        foreach ([
            TokenFactory::class,
            RefreshTokenGuard::class,
            TokenIssuer::class,
            TokenRotation::class,
            TokenLogout::class,
            TokenSessionRevoker::class,
            AccessTokenVerifier::class,
            AuthenticatedTokenResolver::class,
            PasswordLogin::class,
            PasswordResetDispatch::class,
            EmailVerificationDispatch::class,
            ProfileEmailChangeCompletion::class,
            ProfileEmailChangeDispatch::class,
            AdminInvitationDispatch::class,
            AppInvitationDispatch::class,
        ] as $service) {
            $builder->register($service, $service)->setAutowired(true);
        }
        $builder->getDefinition(ProfileEmailChangeCompletion::class)
            ->setArgument('$db', new Reference('doctrine.dbal.default_connection'));
        $builder->getDefinition(PasswordLogin::class)
            ->setArgument('$secondFactors', new TaggedIteratorArgument('symsvel.auth.second_factor'));
    }
}
