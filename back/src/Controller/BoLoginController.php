<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use SymSvel\Module\Auth\Identity\PasswordLogin;

/**
 * BO password login. Token transport and browser session wiring are separate steps.
 */
final readonly class BoLoginController
{
    public function __construct(private PasswordLogin $login)
    {
    }

    #[Route('/apibo/auth/login', name: 'symsvel_auth_bo_login', methods: ['POST'], format: 'json')]
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

        if (!is_array($payload) || !is_string($payload['email'] ?? null) || !is_string($payload['password'] ?? null)
            || strlen($payload['email']) > 254 || strlen($payload['password']) > 4096) {
            return new JsonResponse(['error' => ['code' => 'invalid_request', 'message' => 'Invalid request.']], 400);
        }

        $pair = $this->login->login('bo', $payload['email'], $payload['password'], new \DateTimeImmutable('now', new \DateTimeZone('UTC')));
        if ($pair === null) {
            return new JsonResponse(['error' => ['code' => 'invalid_credentials', 'message' => 'Invalid credentials.']], 401);
        }

        $response = new JsonResponse([
            'access_token' => $pair->access->raw,
            'expires_at' => $pair->access->expiresAt->format(\DateTimeInterface::ATOM),
            'refresh_token' => $pair->refresh->raw,
            'refresh_expires_at' => $pair->refresh->expiresAt->format(\DateTimeInterface::ATOM),
            'token_type' => 'Bearer',
        ]);
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');

        return $response;
    }
}
