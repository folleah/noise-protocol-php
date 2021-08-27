<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\Language;

use Invariance\NoiseProtocol\Exception\NoiseProtocolException;

class PreMessagePattern
{
    /**
     * @var string[]
     */
    private $tokens;

    public static function S(): self
    {
        return new self([Token::S]);
    }

    public static function E(): self
    {
        return new self([Token::E]);
    }

    public static function ES(): self
    {
        return new self([Token::E, Token::S]);
    }

    public static function empty(): self
    {
        return new self();
    }

    public function __construct(array $tokens = [])
    {
        $this->tokens = $tokens;
    }

    /**
     * @return string[]
     */
    public function getTokens(): array
    {
        return $this->tokens;
    }

    public function hasToken(string $token): bool
    {
        return in_array($token, $this->tokens, true);
    }
}