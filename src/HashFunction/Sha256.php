<?php

namespace Invariance\NoiseProtocol\HashFunction;

class Sha256 implements HashFunction
{
    public function getHashLen(): int
    {
        return 32;
    }

    public function getBlockLen(): int
    {
        return 64;
    }

    public function hash(string $input): string
    {
        return hash('sha256', $input);
    }

    public function __toString(): string
    {
        return 'SHA256';
    }
}