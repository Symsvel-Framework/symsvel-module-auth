<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use SymSvel\Module\Auth\Identity\AppInvitationCompletion;

/** Public one-time App activation, never usable as a BO login or password reset. */
final readonly class AppInvitationCompleteController
{
    public function __construct(private AppInvitationCompletion $completion) {}

    #[Route('/apiopen/auth/invitation/complete', name: 'symsvel_auth_app_invitation_complete', methods: ['POST'], format: 'json')]
    public function __invoke(Request $request): JsonResponse
    {
        if (!str_starts_with(strtolower($request->headers->get('Content-Type', '')), 'application/json')) {
            return self::answer(['error' => ['code' => 'unsupported_media_type']], 415);
        }
        $raw = $request->getContent();
        if (strlen($raw) > 8192) return self::answer(['error' => ['code' => 'invalid_request']], 400);
        try {
            $payload = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return self::answer(['error' => ['code' => 'invalid_request']], 400);
        }
        if (!is_array($payload) || array_is_list($payload)
            || array_diff(array_keys($payload), ['token', 'password'])
            || !is_string($payload['token'] ?? null)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $payload['token'])
            || !is_string($payload['password'] ?? null)
            || strlen($payload['password']) < 12 || strlen($payload['password']) > 1024
            || str_contains($payload['password'], "\0")) {
            return self::answer(['error' => ['code' => 'invalid_request']], 400);
        }
        $done = $this->completion->complete(
            $payload['token'], $payload['password'], new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
        );
        return $done ? self::answer(['status' => 'completed'])
            : self::answer(['error' => ['code' => 'invalid_invitation_token']], 400);
    }

    private static function answer(array $payload, int $status = 200): JsonResponse
    {
        $response = new JsonResponse($payload, $status);
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');
        return $response;
    }

