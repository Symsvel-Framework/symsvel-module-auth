<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Service;

/** Authentication URLs are calculated from trusted deploy/Setup origins. */
final readonly class PasswordResetUrlResolver
{
    public function __construct(private AuthPageUrls $pages)
    {
    }

    public function forContext(string $context): string
    {
        return $this->pages->forPage($context, 'reset');
    }
}
