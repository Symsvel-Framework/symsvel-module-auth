<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Service;

/** No user-controlled URL or access to private Setup files. */
final readonly class EmailVerificationUrlResolver
{
    public function __construct(private AuthPageUrls $pages)
    {
    }

    public function forContext(string $context): string
    {
        return $this->pages->forPage($context, 'verify');
    }
}
