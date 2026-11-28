<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

use Symfony\Component\DependencyInjection\Attribute\AutoconfigureTag;

/** An authentication extension deletes only its own App-principal data. */
#[AutoconfigureTag('symsvel.auth.app_principal_security_contributor')]
interface AppPrincipalSecurityContributor
{
    public function moduleId(): string;

    /** Must use the existing shared transaction, with no external effects. */
    public function eraseAppPrincipal(int $userId): void;
}
