<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Identity;

/** Declares the unique context owned by an identity provider. */
interface ContextOwnedIdentity
{
    public function authContext(): string;
}
