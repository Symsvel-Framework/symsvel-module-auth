<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use SymSvel\Module\Auth\Identity\PasswordResetCompletion;

/** Public completion routes; no account information is disclosed. */
final readonly class PasswordResetCompleteController
{
    public function __construct(private PasswordResetCompletion $completion)
    {
    }

    #[Route('/apibo/auth/password-reset/complete', name: 'symsvel_auth_bo_reset_complete', methods: ['POST'], format: 'json')]
    public function bo(Request $request): JsonResponse
    {
        return $this->complete($request, 'bo');
    }

    #[Route('/api/auth/password-reset/complete', name: 'symsvel_auth_app_reset_complete', methods: ['POST'], format: 'json')]
    public function app(Request $request): JsonResponse
    {
        return $this->complete($request, 'app');
    }

    private function complete(Request $request, string $context): JsonResponse
    {
        if (!str_starts_with(strtolower($request->headers->get('Content-Type', '')), 'application/json')) {
            return $this->response(['error' => ['code' => 'unsupported_media_type', 'message' => 'JSON required.']], 415);
        }

        try {
            $payload = json_decode($request->getContent(), true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return $this->response(['error' => ['code' => 'invalid_request', 'message' => 'Invalid request.']], 400);
        }

        if (!is_array($payload) || !is_string($payload['token'] ?? null)
            || !is_string($payload['password'] ?? null)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $payload['token'])
            || strlen($payload['password']) < 12 || strlen($payload['password']) > 1024) {
            return $this->response(['error' => ['code' => 'invalid_request', 'message' => 'Invalid request.']], 400);
        }

        $completed = $this->completion->complete(
            $context,
            $payload['token'],
            $payload['password'],
            new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
        );

        return $completed
            ? $this->response(['status' => 'completed'])
            : $this->response(['error' => ['code' => 'invalid_reset_token', 'message' => 'Reset token invalid or expired.']], 400);
    }

    private function response(array $data, int $status = 200): JsonResponse
    {
        $response = new JsonResponse($data, $status);
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');

        return $response;
    }
}
