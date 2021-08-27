<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\Language;

final class MessagePattern
{
    /**
     * @var string[]
     */
    private $tokens;

    public function __construct(...$tokens)
    {
        $this->tokens = $tokens;
    }

    public function hasToken(string $token): bool
    {
        return in_array($token, $this->tokens, true);
    }
}