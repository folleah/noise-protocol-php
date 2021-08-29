<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\HashFunction;

final class Sha512 implements HashFunction
{
    public function getHashLen(): int
    {
        return 64;
    }

    public function hash(string $input): string
    {
        return hash($this->__toString(), $input);
    }

    public function __toString(): string
    {
        return 'SHA512';
    }
}