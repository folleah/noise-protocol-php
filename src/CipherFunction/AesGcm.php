<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\CipherFunction;

use Invariance\NoiseProtocol\Exception\DecryptFailureException;
use Invariance\NoiseProtocol\Exception\NoiseProtocolException;

class AesGcm implements CipherFunction
{
    public function __construct()
    {
        if (!sodium_crypto_aead_aes256gcm_is_available()) {
            throw new NoiseProtocolException("AesGcm cipher function is not available.");
        }
    }

    /**
     * @inheritDoc
     */
    public function encrypt(string $k, string $n, string $ad, string $plainText): string
    {
        return sodium_crypto_aead_aes256gcm_encrypt(
            $plainText,
            $ad,
            $n,
            $k
        );
    }

    /**
     * @inheritDoc
     */
    public function decrypt(string $k, string $n, string $ad, string $cipherText): string
    {
        $res = sodium_crypto_aead_aes256gcm_decrypt(
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
        return random_bytes(SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES);
    }

    public function __toString(): string
    {
        return 'AESGCM';
    }
}