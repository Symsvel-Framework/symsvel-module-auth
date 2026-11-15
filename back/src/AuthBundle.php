<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Argument\TaggedIteratorArgument;
use SymSvel\Module\Auth\Controller\BoLoginController;
use SymSvel\Module\Auth\Controller\BoRefreshController;
use SymSvel\Module\Auth\Controller\BoLogoutController;
use SymSvel\Module\Auth\Controller\BoSessionController;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use SymSvel\Module\Auth\Identity\AuthenticatedTokenResolver;
use SymSvel\Module\Auth\Identity\ContextIdentityProvider;
use SymSvel\Module\Auth\Identity\PasswordPrincipal;
use SymSvel\Module\Auth\Identity\PrincipalStatus;
use SymSvel\Module\Auth\Identity\PasswordLogin;
use SymSvel\Module\Auth\Mail\AuthMailTemplateProvider;
use SymSvel\Module\Auth\Token\AccessTokenLookup;
use SymSvel\Module\Auth\Token\BoSessionLogout;
use SymSvel\Module\Auth\Token\AccessTokenVerifier;
use SymSvel\Module\Auth\Token\DbalTokenStore;
use SymSvel\Module\Auth\Token\RefreshTokenGuard;
use SymSvel\Module\Auth\Token\TokenFactory;
use SymSvel\Module\Auth\Token\TokenIssuer;
use SymSvel\Module\Auth\Token\TokenLogout;
use SymSvel\Module\Auth\Token\TokenRotation;
use SymSvel\Module\Auth\Token\TokenSessionRevoker;
use SymSvel\Module\Auth\Token\TokenStore;

final class AuthBundle extends AbstractBundle
{
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $builder->register(AuthMailTemplateProvider::class, AuthMailTemplateProvider::class)
            ->addTag('symsvel.mails.template_provider');

        // Reuse the same DBAL connection as the host application.
        $builder->register(DbalTokenStore::class, DbalTokenStore::class)
            ->setArgument('$connection', new Reference('doctrine.dbal.default_connection'));

        $builder->setAlias(TokenStore::class, DbalTokenStore::class);
        $builder->setAlias(AccessTokenLookup::class, DbalTokenStore::class);

        $builder->register(BoSessionLogout::class, BoSessionLogout::class)
            ->setArgument('$connection', new Reference('doctrine.dbal.default_connection'));

        $builder->register(ContextIdentityProvider::class, ContextIdentityProvider::class)
            ->setAutowired(true)
            ->setArgument('$providers', new TaggedIteratorArgument('symsvel.auth.identity_provider'));
        $builder->setAlias(PasswordPrincipal::class, ContextIdentityProvider::class);
        $builder->setAlias(PrincipalStatus::class, ContextIdentityProvider::class);

        foreach ([BoLoginController::class, BoSessionController::class, BoLogoutController::class, BoRefreshController::class] as $controller) {
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
        ] as $service) {
            $builder->register($service, $service)->setAutowired(true);
        }
    }
}
