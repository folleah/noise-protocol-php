<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\CipherFunction;

use Invariance\NoiseProtocol\Exception\DecryptFailureException;

class ChaChaPoly implements CipherFunction
{
    /**
     * @inheritDoc
     */
    public function encrypt(string $k, int $n, string $ad, string $plainText): string
    {
        return sodium_crypto_aead_chacha20poly1305_encrypt(
            $plainText,
            $ad,
            $n,
            $k
        );
    }

    /**
     * @inheritDoc
     */
    public function decrypt(string $k, int $n, string $ad, string $cipherText): string
    {
        $res = sodium_crypto_aead_chacha20poly1305_decrypt(
            $cipherText,
            $ad,
            $n,
            $k
        );

        if ($res === false) {
            throw new DecryptFailureException();
        }

        return $res;
    }

    /**
     * @inheritDoc
     */
    public function reKey(): string
    {
        return random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES);
    }

    public function __toString(): string
    {
        return 'ChaChaPoly';
    }
}