<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\CipherFunction;

use Invariance\NoiseProtocol\Exception\DecryptFailureException;

interface CipherFunction
{
    /**
     * @param string $k - cipher key
     * @param string $n - nonce
     * @param string $ad - additional data
     * @param string $plainText - plain text
     * @return string - cipher text
     */
    public function encrypt(string $k, string $n, string $ad, string $plainText): string;

    /**
     * @param string $k - cipher key
     * @param string $n - nonce
     * @param string $ad - additional data
     * @param string $cipherText - cipher text
     * @return string - plain text
     *
     * @throws DecryptFailureException
     */
    public function decrypt(string $k, string $n, string $ad, string $cipherText): string;

    /**
     * @return string - pseudo-random bytes cipher key
     */
    public function reKey(): string;

    /**
     * @return string - Function name
     */
    public function __toString(): string;
}