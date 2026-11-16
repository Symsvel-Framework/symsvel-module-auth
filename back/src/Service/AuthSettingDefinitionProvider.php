<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Service;

use SymSvel\Module\Settings\Service\SettingDefinition;
use SymSvel\Module\Settings\Service\SettingDefinitionProviderInterface;

/** Auth declares its trusted password reset pages; Settings owns their persistence. */
final class AuthSettingDefinitionProvider implements SettingDefinitionProviderInterface
{
    /** @return iterable<SettingDefinition> */
    public function definitions(): iterable
    {
        yield new SettingDefinition(
            key: 'bo_reset_url',
            label: 'URL de récupération du mot de passe BO',
            group: 'authentication',
            type: 'url',
            description: 'URL HTTPS publique de la page BO de changement de mot de passe, sans paramètre.',
        );
        yield new SettingDefinition(
            key: 'bo_verify_email_url',
            label: 'URL de confirmation d’adresse e-mail BO',
            group: 'authentication',
            type: 'url',
            description: 'URL HTTPS de confirmation BO, sans paramètres de requête.',
        );
        yield new SettingDefinition(
            key: 'bo_invitation_url',
            label: 'URL d’activation d’une invitation administrateur BO',
            group: 'authentication',
            type: 'url',
            description: 'URL HTTPS de création du premier mot de passe BO, sans paramètre.',
        );
        yield new SettingDefinition(
            key: 'app_reset_url',
            label: 'URL de récupération du mot de passe App',
            group: 'authentication',
            type: 'url',
            description: 'URL HTTPS publique de la page App de changement de mot de passe, sans paramètre, si App est installée.',
        );
    }
}
