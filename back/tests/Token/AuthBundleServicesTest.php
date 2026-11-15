<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Tests\Token;

use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Argument\TaggedIteratorArgument;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;
use SymSvel\Module\Auth\AuthBundle;
use SymSvel\Module\Auth\Identity\PasswordLogin;
use SymSvel\Module\Auth\Identity\PasswordResetLimiter;
use SymSvel\Module\Auth\Identity\ContextIdentityProvider;
use SymSvel\Module\Auth\Identity\PasswordPrincipal;
use SymSvel\Module\Auth\Identity\PrincipalStatus;
use SymSvel\Module\Auth\Identity\AuthenticatedTokenResolver;
use SymSvel\Module\Auth\Token\AccessTokenLookup;
use SymSvel\Module\Auth\Token\AccessTokenVerifier;
use SymSvel\Module\Auth\Token\DbalTokenStore;
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

        self::assertSame(ContextIdentityProvider::class, (string) $builder->getAlias(PasswordPrincipal::class));
        self::assertSame(ContextIdentityProvider::class, (string) $builder->getAlias(PrincipalStatus::class));
        self::assertTrue($builder->getDefinition(ContextIdentityProvider::class)->isAutowired());
        $providers = $builder->getDefinition(ContextIdentityProvider::class)->getArgument('$providers');
        self::assertInstanceOf(TaggedIteratorArgument::class, $providers);
        self::assertSame('symsvel.auth.identity_provider', $providers->getTag());

        self::assertSame(DbalTokenStore::class, (string) $builder->getAlias(TokenStore::class));
        self::assertSame(DbalTokenStore::class, (string) $builder->getAlias(AccessTokenLookup::class));

        $connection = $builder->getDefinition(DbalTokenStore::class)->getArgument('$connection');
        self::assertInstanceOf(Reference::class, $connection);
        self::assertSame('doctrine.dbal.default_connection', (string) $connection);

        foreach ([
            PasswordLogin::class,
            PasswordResetLimiter::class,
            AuthenticatedTokenResolver::class,
            TokenIssuer::class,
            TokenRotation::class,
            TokenLogout::class,
            TokenSessionRevoker::class,
            AccessTokenVerifier::class,
            PasswordResetLimiter::class,
        ] as $service) {
            self::assertTrue($builder->hasDefinition($service), $service.' must be registered.');
            self::assertTrue($builder->getDefinition($service)->isAutowired());
        }
    }
}
