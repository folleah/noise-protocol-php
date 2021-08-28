<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\Language;

final class MessagePattern implements \Iterator
{
    /**
     * @var string[]
     */
    private $tokens;

    /**
     * @var int
     */
    private $position = 0;

    public function __construct(...$tokens)
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