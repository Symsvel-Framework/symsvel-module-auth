<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use SymSvel\Module\Auth\Token\RefreshDecision;
use SymSvel\Module\Auth\Token\TokenRotation;

final readonly class BoRefreshController
{
    public function __construct(private TokenRotation $rotation)
    {
    }

    #[Route('/apibo/auth/refresh', name: 'symsvel_auth_bo_refresh', methods: ['POST'], format: 'json')]
    public function __invoke(Request $request): JsonResponse
    {
        if (!str_starts_with(strtolower($request->headers->get('Content-Type', '')), 'application/json')) {
            return new JsonResponse(['error' => ['code' => 'unsupported_media_type', 'message' => 'JSON required.']], 415);
        }

        try {
            $payload = json_decode($request->getContent(), true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return new JsonResponse(['error' => ['code' => 'invalid_request', 'message' => 'Invalid request.']], 400);
        }

        if (!is_array($payload) || !is_string($payload['refresh_token'] ?? null)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $payload['refresh_token'])) {
            return new JsonResponse(['error' => ['code' => 'invalid_request', 'message' => 'Invalid request.']], 400);
        }

        $result = $this->rotation->rotate($payload['refresh_token'], 'bo', new \DateTimeImmutable('now', new \DateTimeZone('UTC')));
        if ($result->decision !== RefreshDecision::Rotate || $result->pair === null) {
            $response = new JsonResponse(['error' => ['code' => 'invalid_session', 'message' => 'Session expired or invalid.']], 401);
        } else {
            $pair = $result->pair;
            $response = new JsonResponse([
                'access_token' => $pair->access->raw,
                'expires_at' => $pair->access->expiresAt->format(\DateTimeInterface::ATOM),
                'refresh_token' => $pair->refresh->raw,
                'refresh_expires_at' => $pair->refresh->expiresAt->format(\DateTimeInterface::ATOM),
                'token_type' => 'Bearer',
            ]);
        }
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');

        return $response;
    }
}
