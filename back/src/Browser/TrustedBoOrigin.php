<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Browser;

use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\HttpFoundation\Request;

/** The BO Origin is trusted configuration, never inferred from Host. */
final readonly class TrustedBoOrigin
{
    public function __construct(
        #[Autowire('%kernel.project_dir%')] private string $backendDirectory,
        private ?string $explicitOrigin = null,
    ) {
    }

    public function accepts(Request $request): bool
    {
        $given = $request->headers->get('Origin');
        $expected = $this->expected();
        return is_string($given) && $expected !== null && hash_equals($expected, $given);
    }

    private function expected(): ?string
    {
        $override = $this->explicitOrigin ?? ($_SERVER['SYMSVEL_BO_ORIGIN'] ?? $_ENV['SYMSVEL_BO_ORIGIN'] ?? null);
        if (is_string($override) && $override !== '') {
            $url = parse_url($override);
            if (!is_array($url) || ($url['scheme'] ?? null) !== 'https'
                || empty($url['host']) || isset($url['user']) || isset($url['pass'])
                || isset($url['path']) || isset($url['query']) || isset($url['fragment'])
                || preg_match('/[\r\n]/', $override)) {
                return null;
            }
            return $override;
        }
        $path = dirname($this->backendDirectory).'/.symsvel/project.json';
        if (!is_file($path) || !is_readable($path) || is_link($path)) {
            return null;
        }
        try {
            $data = json_decode((string) file_get_contents($path), true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }
        $domain = is_array($data) ? ($data['local_domain'] ?? null) : null;
        if (($data['schema'] ?? null) !== 1 || !is_string($domain)
            || !preg_match('/^(?=.{1,253}$)[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)*$/D', $domain)) {
            return null;
        }
        return 'https://bo.'.$domain;
    }
}
