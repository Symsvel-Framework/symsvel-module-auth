<?php

declare(strict_types=1);

namespace SymSvel\Module\Auth\Controller;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use SymSvel\Module\Auth\Identity\AuthenticatedTokenResolver;

/**
 * Minimal authenticated BO identity endpoint; roles and ACLs remain external.
 */
final readonly class BoSessionController
{
    public function __construct(private AuthenticatedTokenResolver $tokens)
    {
    }

    #[Route('/apibo/auth/me', name: 'symsvel_auth_bo_me', methods: ['GET'], format: 'json')]
    public function __invoke(Request $request): JsonResponse
    {
        $authorization = $request->headers->get('Authorization', '');
        if (!preg_match('/^Bearer ([A-Za-z0-9_-]{43})$/D', $authorization, $matches)) {
            return $this->unauthorized();
        }

        $subject = $this->tokens->resolve($matches[1], 'bo', new \DateTimeImmutable('now', new \DateTimeZone('UTC')));
        if ($subject === null) {
            return $this->unauthorized();
        }

        $response = new JsonResponse(['id' => $subject->id, 'context' => $subject->context]);
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }

    private function unauthorized(): JsonResponse
    {
        $response = new JsonResponse(['error' => ['code' => 'unauthorized', 'message' => 'Authentication required.']], 401);
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }
}
