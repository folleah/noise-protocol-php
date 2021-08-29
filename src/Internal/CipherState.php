<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\Internal;

use Invariance\NoiseProtocol\Exception\DecryptFailureException;
use Invariance\NoiseProtocol\ProtocolSuite;

class CipherState
{
    /**
     * @var int
     */
    private $n;

    /**
     * @var string|null
     */
    private $k;

    /**
     * @var ProtocolSuite
     */
    private $suite;

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

    public function encryptWithAd(string $ad, string $plainText): string
    {
        if ($this->hasKey()) {
            return $this->suite->getCipherFunction()->encrypt($this->k, $this->n++, $ad, $plainText);
        }

        return $plainText;
    }

    public function decryptWithAd(string $ad, string $cipherText): string
    {
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