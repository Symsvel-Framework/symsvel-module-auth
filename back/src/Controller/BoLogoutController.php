<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use SymSvel\Module\Auth\Identity\AuthenticatedTokenResolver;
use SymSvel\Module\Auth\Token\TokenLogout;

/**
 * BO logout requires both the current access token and its refresh secret.
 * The refresh secret selects the family to revoke; it is never logged.
 */
final readonly class BoLogoutController
{
    public function __construct(
        private AuthenticatedTokenResolver $tokens,
        private TokenLogout $logout,
    ) {
    }

    #[Route('/apibo/auth/logout', name: 'symsvel_auth_bo_logout', methods: ['POST'], format: 'json')]
    public function __invoke(Request $request): JsonResponse
    {
        $authorization = $request->headers->get('Authorization', '');
        if (!preg_match('/^Bearer ([A-Za-z0-9_-]{43})$/D', $authorization, $matches)
            || $this->tokens->resolve($matches[1], 'bo', new \DateTimeImmutable('now', new \DateTimeZone('UTC'))) === null) {
            return $this->error(401, 'unauthorized');
        }

        if (!str_starts_with(strtolower($request->headers->get('Content-Type', '')), 'application/json')) {
            return $this->error(415, 'unsupported_media_type');
        }

        try {
            $payload = json_decode($request->getContent(), true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return $this->error(400, 'invalid_request');
        }

        if (!is_array($payload) || !is_string($payload['refresh_token'] ?? null)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $payload['refresh_token'])) {
            return $this->error(400, 'invalid_request');
        }

        // The token service verifies the refresh context and revokes its family.
        // A future session transport must bind both secrets to the same session.
        if (!$this->logout->logout($payload['refresh_token'], 'bo', new \DateTimeImmutable('now', new \DateTimeZone('UTC')))) {
            return $this->error(401, 'invalid_session');
        }

        $response = new JsonResponse(null, 204);
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }

    private function error(int $status, string $code): JsonResponse
    {
        $response = new JsonResponse(['error' => ['code' => $code, 'message' => 'Request rejected.']], $status);
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }
}
