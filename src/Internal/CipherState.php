<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\Internal;

use Invariance\NoiseProtocol\Exception\DecryptFailureException;
use Invariance\NoiseProtocol\Protocol;

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
     * @var Protocol
     */
    private $protocol;

    public function __construct(Protocol $protocol)
    {
        $this->protocol = $protocol;
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
            return $this->protocol->getCipherFunction()->encrypt($this->k, (string)$this->n++, $ad, $plainText);
        }

        return $plainText;
    }

    public function decryptWithAd(string $ad, string $cipherText): string
    {
        if ($this->hasKey()) {
            try {
                return $this->protocol->getCipherFunction()->decrypt($this->k, (string)$this->n++, $ad, $cipherText);
            } catch (DecryptFailureException $e) {
                $this->n--;
                throw $e;
            }
        }

        return $cipherText;
    }

    public function reKey(): void
    {
        $this->k = $this->protocol->getCipherFunction()->reKey();
    }
}