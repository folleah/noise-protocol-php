<?php

namespace Invariance\NoiseProtocol\HashFunction;

class Sha512 implements HashFunction
{
    public function getHashLen(): int
    {
        return 64;
    }

    public function getBlockLen(): int
    {
        return 128;
    }

    public function hash(string $input): string
    {
        return hash('sha512', $input);
    }

    public function __toString(): string
    {
        return 'SHA512';
    }
}