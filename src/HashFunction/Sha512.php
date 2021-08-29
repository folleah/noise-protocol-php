<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\HashFunction;

use JetBrains\PhpStorm\Pure;

final class Sha512 implements HashFunction
{
    public function getHashLen(): int
    {
        return 64;
    }

    #[Pure] public function hash(string $input): string
    {
        return hash($this->__toString(), $input);
    }

    public function __toString(): string
    {
        return 'SHA512';
    }
}