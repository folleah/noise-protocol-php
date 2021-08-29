<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\Internal;

use Invariance\NoiseProtocol\Exception\DecryptFailureException;
use Invariance\NoiseProtocol\ProtocolSuite;

final class CipherState
{
    private int $n;

    private string|null $k;

    private ProtocolSuite $suite;

    public function __construct(ProtocolSuite $suite)
    {
        $this->suite = $suite;
    }

    public function initializeKey(?string $key): void
    {
        $this->k = $key;
        $this->n = 0;
    }

    public function hasKey(): bool
    {
        return $this->k !== null;
    }

    public function setNonce(int $nonce)
    {
        $this->n = $nonce;
    }

    public function encryptWithAd(string $plainText, string|null $ad = null): string
    {
        if ($ad === null) {
            $ad = '';
        }
        if ($this->hasKey()) {
            return $this->suite->getCipherFunction()->encrypt($this->k, $this->n++, $ad, $plainText);
        }

        return $plainText;
    }

    public function decryptWithAd(string $cipherText, string|null $ad = null): string
    {
        if ($ad === null) {
            $ad = '';
        }
        if ($this->hasKey()) {
            try {
                return $this->suite->getCipherFunction()->decrypt($this->k, $this->n++, $ad, $cipherText);
            } catch (DecryptFailureException $e) {
                $this->n--;
                throw $e;
            }
        }

        return $cipherText;
    }

    public function reKey(): void
    {
        $this->k = $this->suite->getCipherFunction()->reKey();
    }
}