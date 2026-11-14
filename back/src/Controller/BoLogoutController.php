<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use SymSvel\Module\Auth\Token\BoSessionLogout;

final readonly class BoLogoutController
{
    public function __construct(private BoSessionLogout $logout)
    {
    }

    #[Route('/apibo/auth/logout', name: 'symsvel_auth_bo_logout', methods: ['POST'], format: 'json')]
    public function __invoke(Request $request): JsonResponse
    {
        $authorization = $request->headers->get('Authorization', '');
        if (!preg_match('/^Bearer ([A-Za-z0-9_-]{43})$/D', $authorization, $matches)) {
            return $this->error(401);
        }

        try {
            $payload = json_decode($request->getContent(), true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return $this->error(400);
        }
        if (!str_starts_with(strtolower($request->headers->get('Content-Type', '')), 'application/json')
            || !is_array($payload) || !is_string($payload['refresh_token'] ?? null)) {
            return $this->error(400);
        }

        if (!$this->logout->logout($matches[1], $payload['refresh_token'], new \DateTimeImmutable('now', new \DateTimeZone('UTC')))) {
            return $this->error(401);
        }

        $response = new JsonResponse(null, 204);
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }

    private function error(int $status): JsonResponse
    {
        $response = new JsonResponse(['error' => ['code' => 'invalid_session', 'message' => 'Request rejected.']], $status);
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }
}
