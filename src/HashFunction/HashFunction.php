<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\HashFunction;

interface HashFunction
{
    public function getHashLen(): int;

    public function hash(string $input): string;

    /**
     * @return string - Function name
     */
    public function __toString(): string;
}