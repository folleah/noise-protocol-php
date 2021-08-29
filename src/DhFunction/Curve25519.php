<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\DhFunction;

use Invariance\NoiseProtocol\KeyPair;

final class Curve25519 implements DhFunction
{
    public function generateKeyPair(): KeyPair
    {
        $privateKey = random_bytes($this->getLen());
        $publicKey = sodium_crypto_scalarmult_base($privateKey);

        return new KeyPair(
            $privateKey,
            $publicKey
        );
    }

    public function getLen(): int
    {
        return SODIUM_CRYPTO_SCALARMULT_SCALARBYTES;
    }

    public function dh(KeyPair $l_KeyPair, string $r_PublicKey): string
    {
        return sodium_crypto_scalarmult($l_KeyPair->getSecretKey(), $r_PublicKey);
    }

    public function __toString(): string
    {
        return '25519';
    }
}