<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Token;

/** Storage abstraction; no Symfony user provider dependency. */
interface AccessTokenLookup
{
    public function findAccessByHash(string $hash): ?AccessTokenRecord;
}
