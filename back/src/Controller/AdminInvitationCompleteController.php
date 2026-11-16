<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use SymSvel\Module\Auth\Identity\AdminInvitationCompletion;

final readonly class AdminInvitationCompleteController
{
    public function __construct(private AdminInvitationCompletion $completion) {}

    #[Route('/apibo/auth/invitation/complete', name: 'symsvel_auth_bo_invitation_complete', methods: ['POST'], format: 'json')]
    public function bo(Request $request): JsonResponse
    {
        if (!str_starts_with(strtolower($request->headers->get('Content-Type', '')), 'application/json')) {
            return self::response(['error' => ['code' => 'unsupported_media_type', 'message' => 'JSON required.']], 415);
        }
        $raw = $request->getContent();
        if (strlen($raw) > 8192) {
            return self::response(['error' => ['code' => 'invalid_request', 'message' => 'Invalid request.']], 400);
        }
        try {
            $data = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return self::response(['error' => ['code' => 'invalid_request', 'message' => 'Invalid request.']], 400);
        }
        if (!is_array($data) || !is_string($data['token'] ?? null)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $data['token'])
            || !is_string($data['password'] ?? null)
            || strlen($data['password']) < 12 || strlen($data['password']) > 1024
            || str_contains($data['password'], "\0")) {
            return self::response(['error' => ['code' => 'invalid_request', 'message' => 'Invalid request.']], 400);
        }

        $completed = $this->completion->complete(
            $data['token'], $data['password'], new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
        );
        return $completed
            ? self::response(['status' => 'completed'])
            : self::response(['error' => ['code' => 'invalid_invitation_token', 'message' => 'Invitation invalid or expired.']], 400);
    }

    private static function response(array $data, int $status = 200): JsonResponse
    {
        $response = new JsonResponse($data, $status);
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');
        return $response;
    }
}
