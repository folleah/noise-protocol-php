<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\CipherFunction;

use Invariance\NoiseProtocol\ByteHelper;
use Invariance\NoiseProtocol\Exception\DecryptFailureException;
use Invariance\NoiseProtocol\Exception\NoiseProtocolException;

final class ChaChaPoly implements CipherFunction
{
    /**
     * @inheritDoc
     */
    public function encrypt(string $k, int $n, string $ad, string $plainText): string
    {
        $keyLength = strlen($k);
        if ($keyLength !== SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES) {
            throw new NoiseProtocolException('Key length must be %s bytes, %s bytes provided.', SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES, $keyLength);
        }

        return sodium_crypto_aead_chacha20poly1305_encrypt(
            $plainText,
            $ad,
            ByteHelper::intAlloc($n, SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES),
            $k
        );
    }

    /**
     * @inheritDoc
     */
    public function decrypt(string $k, int $n, string $ad, string $cipherText): string
    {
        $keyLength = strlen($k);
        if ($keyLength !== SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES) {
            throw new NoiseProtocolException('Key length must be %s bytes, %s bytes provided.', SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES, $keyLength);
        }

        $res = sodium_crypto_aead_chacha20poly1305_decrypt(
            $cipherText,
            $ad,
            ByteHelper::intAlloc($n, SODIUM_CRYPTO_AEAD_AES256GCM_NPUBBYTES),
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