<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Controller;

use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use SymSvel\Module\Auth\Identity\PasswordResetCompletion;
use SymSvel\Module\Auth\Identity\PasswordResetDispatch;

/**
 * Public App password recovery. Only confirmed account mailboxes can receive
 * links, and HTTP responses never disclose whether an account exists.
 */
final readonly class AppPasswordResetController
{
    public function __construct(
        private PasswordResetDispatch $dispatch,
        private PasswordResetCompletion $completion,
        private LoggerInterface $logger,
    ) {
    }

    #[Route('/apiopen/auth/password-reset/request', name: 'symsvel_auth_app_password_reset_request', methods: ['POST'], format: 'json')]
    public function request(Request $request): JsonResponse
    {
        $data = self::payload($request);
        if ($data instanceof JsonResponse) {
            return $data;
        }
        if (!is_string($data['email'] ?? null)
            || strlen($data['email']) > 254
            || filter_var(trim($data['email']), FILTER_VALIDATE_EMAIL) === false
            || !in_array($data['locale'] ?? 'fr', ['fr', 'en'], true)) {
            return self::response(['error' => ['code' => 'invalid_request']], 400);
        }

        try {
            $this->dispatch->dispatch(
                'app',
                strtolower(trim($data['email'])),
                $data['locale'] ?? 'fr',
                (string) $request->getClientIp(),
                new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
            );
        } catch (\Exception $exception) {
            // Preserve the same public response for absent accounts and failed delivery.
            $this->logger->error('App password reset dispatch failed.', ['exception' => $exception]);
        }
        return self::response(['status' => 'accepted'], 202);
    }

    #[Route('/apiopen/auth/password-reset/complete', name: 'symsvel_auth_app_password_reset_complete', methods: ['POST'], format: 'json')]
    public function complete(Request $request): JsonResponse
    {
        $data = self::payload($request);
        if ($data instanceof JsonResponse) {
            return $data;
        }
        if (!is_string($data['token'] ?? null)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $data['token'])
            || !is_string($data['password'] ?? null)
            || strlen($data['password']) < 12 || strlen($data['password']) > 1024
            || str_contains($data['password'], "\0")) {
            return self::response(['error' => ['code' => 'invalid_request']], 400);
        }

        $completed = $this->completion->complete(
            'app', $data['token'], $data['password'],
            new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
        );
        return $completed ? self::response(['status' => 'completed'])
            : self::response(['error' => ['code' => 'invalid_reset_token']], 400);
    }

    /** @return array<string, mixed>|JsonResponse */
    private static function payload(Request $request): array|JsonResponse
    {
        if (!str_starts_with(strtolower($request->headers->get('Content-Type', '')), 'application/json')) {
            return self::response(['error' => ['code' => 'unsupported_media_type']], 415);
        }
        $raw = $request->getContent();
        if (strlen($raw) > 8192) {
            return self::response(['error' => ['code' => 'invalid_request']], 400);
        }
        try {
            $data = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return self::response(['error' => ['code' => 'invalid_request']], 400);
        }
        return is_array($data) && !array_is_list($data)
            ? $data : self::response(['error' => ['code' => 'invalid_request']], 400);
    }

    private static function response(array $data, int $status = 200): JsonResponse
    {
        $response = new JsonResponse($data, $status);
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');
        return $response;
    }
}
