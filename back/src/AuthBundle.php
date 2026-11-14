<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;
use SymSvel\Module\Auth\Identity\AuthenticatedTokenResolver;
use SymSvel\Module\Auth\Identity\PasswordLogin;
use SymSvel\Module\Auth\Token\AccessTokenLookup;
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
        // Reuse the same DBAL connection as the host application.
        $builder->register(DbalTokenStore::class, DbalTokenStore::class)
            ->setArgument('$connection', new Reference('doctrine.dbal.default_connection'));

        $builder->setAlias(TokenStore::class, DbalTokenStore::class);
        $builder->setAlias(AccessTokenLookup::class, DbalTokenStore::class);

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
