<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Service;

use SymSvel\Module\Settings\Service\SettingDefinitionProviderInterface;

/**
 * Auth no longer exposes writable callback URLs as Settings.
 * Keep this empty provider through the module-parameter lifecycle so Tooling
 * can synchronize removal of the five legacy auth.*_url definitions.
 */
final class AuthSettingDefinitionProvider implements SettingDefinitionProviderInterface
{
    public function definitions(): iterable
    {
        return [];
    }
}
