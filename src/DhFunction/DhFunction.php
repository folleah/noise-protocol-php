<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\DhFunction;

use Invariance\NoiseProtocol\KeyPair;

interface DhFunction
{
    public function getLen(): int;

    public function generateKeyPair(): KeyPair;

    public function dh(KeyPair $l_KeyPair, string $r_PublicKey): string;

    /**
     * @return string - Function name
     */
    public function __toString(): string;
}