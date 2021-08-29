<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\Language;

final class PreMessagePattern implements \Iterator
{
    /**
     * @var string[]
     */
    private array $tokens;

    private int $position = 0;

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

    public function hasToken(string $token): bool
    {
        return in_array($token, $this->tokens, true);
    }

    public function current(): string
    {
        return $this->tokens[$this->position];
    }

    public function next(): void
    {
        ++$this->position;
    }

    public function key(): int
    {
        return $this->position;
    }

    public function valid(): bool
    {
        return isset($this->tokens[$this->position]);
    }

    public function rewind(): void
    {
        $this->position = 0;
    }
}