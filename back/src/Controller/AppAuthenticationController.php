<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use SymSvel\Module\Auth\Identity\AuthenticatedTokenResolver;
use SymSvel\Module\Auth\Identity\PasswordLogin;
use SymSvel\Module\Auth\Identity\SecondFactorChallenge;
use SymSvel\Module\Auth\Token\ContextSessionLogout;
use SymSvel\Module\Auth\Token\RefreshDecision;
use SymSvel\Module\Auth\Token\TokenRotation;

/** App-only authentication endpoints; Users remains optional in BO-only installations. */
final readonly class AppAuthenticationController
{
    public function __construct(
        private PasswordLogin $login,
        private TokenRotation $rotation,
        private AuthenticatedTokenResolver $access,
        private ContextSessionLogout $logout,
    ) {
    }

    #[Route('/apiopen/auth/login', name: 'symsvel_auth_app_login', methods: ['POST'], format: 'json')]
    public function login(Request $request): JsonResponse
    {
        $payload = self::json($request);
        if ($payload instanceof JsonResponse) {
            return $payload;
        }
        if (!is_string($payload['email'] ?? null) || !is_string($payload['password'] ?? null)
            || strlen($payload['email']) > 254 || strlen($payload['password']) > 4096) {
            return self::answer(['error' => ['code' => 'invalid_request']], 400);
        }
        $pair = $this->login->login(
            'app', $payload['email'], $payload['password'], new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
        );
        if ($pair instanceof SecondFactorChallenge) {
            return self::answer($pair->response(), 202);
        }
        return $pair === null
            ? self::answer(['error' => ['code' => 'invalid_credentials']], 401)
            : self::answer(self::tokens($pair));
    }

    #[Route('/apiopen/auth/second-factor', name: 'symsvel_auth_app_second_factor', methods: ['POST'], format: 'json')]
    public function secondFactor(Request $request): JsonResponse
    {
        $payload = self::json($request);
        if ($payload instanceof JsonResponse) {
            return $payload;
        }
        if (!is_string($payload['challenge'] ?? null) || !is_string($payload['code'] ?? null)) {
            return self::answer(['error' => ['code' => 'invalid_request']], 400);
        }
        $verified = $this->login->completeSecondFactor('app', $payload['challenge'],
            $payload['code'], new \DateTimeImmutable('now', new \DateTimeZone('UTC')));
        return $verified === null
            ? self::answer(['error' => ['code' => 'invalid_second_factor']], 401)
            : self::answer([
                ...self::tokens($verified->tokens),
                ...($verified->recoveryCodes !== [] ? ['recovery_codes' => $verified->recoveryCodes] : []),
            ]);
    }

    #[Route('/apiopen/auth/refresh', name: 'symsvel_auth_app_refresh', methods: ['POST'], format: 'json')]
    public function refresh(Request $request): JsonResponse
    {
        $payload = self::json($request);
        if ($payload instanceof JsonResponse) {
            return $payload;
        }
        if (!is_string($payload['refresh_token'] ?? null)
            || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $payload['refresh_token'])) {
            return self::answer(['error' => ['code' => 'invalid_request']], 400);
        }
        $result = $this->rotation->rotate(
            $payload['refresh_token'], 'app', new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
        );
        return $result->decision === RefreshDecision::Rotate && $result->pair !== null
            ? self::answer(self::tokens($result->pair))
            : self::answer(['error' => ['code' => 'invalid_session']], 401);
    }

    #[Route('/api/auth/me', name: 'symsvel_auth_app_me', methods: ['GET'], format: 'json')]
    public function me(Request $request): JsonResponse
    {
        $token = self::bearer($request);
        if ($token === null) {
            return self::answer(['error' => ['code' => 'unauthorized']], 401);
        }
        $subject = $this->access->resolve(
            $token, 'app', new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
        );
        return $subject === null
            ? self::answer(['error' => ['code' => 'unauthorized']], 401)
            : self::answer(['id' => $subject->id, 'context' => 'app']);
    }

    #[Route('/api/auth/logout', name: 'symsvel_auth_app_logout', methods: ['POST'], format: 'json')]
    public function logout(Request $request): JsonResponse
    {
        $token = self::bearer($request);
        if ($token === null) {
            return self::answer(['error' => ['code' => 'invalid_session']], 401);
        }
        $payload = self::json($request);
        if ($payload instanceof JsonResponse) {
            return $payload;
        }
        if (!is_string($payload['refresh_token'] ?? null)
            || !$this->logout->logout(
                'app', $token, $payload['refresh_token'],
                new \DateTimeImmutable('now', new \DateTimeZone('UTC')),
            )) {
            return self::answer(['error' => ['code' => 'invalid_session']], 401);
        }
        return self::answer(null, 204);
    }

    private static function bearer(Request $request): ?string
    {
        return preg_match('/^Bearer ([A-Za-z0-9_-]{43})$/D', $request->headers->get('Authorization', ''), $found)
            ? $found[1] : null;
    }

    /** @return array<string, mixed>|JsonResponse */
    private static function json(Request $request): array|JsonResponse
    {
        if (!str_starts_with(strtolower($request->headers->get('Content-Type', '')), 'application/json')) {
            return self::answer(['error' => ['code' => 'unsupported_media_type']], 415);
        }
        $body = $request->getContent();
        if (strlen($body) > 8192) {
            return self::answer(['error' => ['code' => 'invalid_request']], 400);
        }
        try {
            $json = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return self::answer(['error' => ['code' => 'invalid_request']], 400);
        }
        return is_array($json) && !array_is_list($json)
            ? $json : self::answer(['error' => ['code' => 'invalid_request']], 400);
    }

    /** @return array<string, string> */
    private static function tokens(\SymSvel\Module\Auth\Token\TokenPair $pair): array
    {
        return [
            'access_token' => $pair->access->raw,
            'expires_at' => $pair->access->expiresAt->format(\DateTimeInterface::ATOM),
            'refresh_token' => $pair->refresh->raw,
            'refresh_expires_at' => $pair->refresh->expiresAt->format(\DateTimeInterface::ATOM),
            'token_type' => 'Bearer',
        ];
    }

    private static function answer(?array $data, int $status = 200): JsonResponse
    {
        $response = new JsonResponse($data, $status);
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');
        return $response;
    }
}
