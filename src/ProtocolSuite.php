<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol;

use Invariance\NoiseProtocol\CipherFunction\CipherFunction;
use Invariance\NoiseProtocol\DhFunction\DhFunction;
use Invariance\NoiseProtocol\HashFunction\HashFunction;

final class ProtocolSuite
{
    private CipherFunction $cipherFunction;

    private HashFunction $hashFunction;

    private DhFunction $dhFunction;


    public function __construct(
        CipherFunction $cipherFunction,
        HashFunction   $hashFunction,
        DhFunction     $dhFunction
    )
    {
        $this->cipherFunction = $cipherFunction;
        $this->hashFunction = $hashFunction;
        $this->dhFunction = $dhFunction;
    }

    public function getCipherFunction(): CipherFunction
    {
        return $this->cipherFunction;
    }

    public function getHashFunction(): HashFunction
    {
        return $this->hashFunction;
    }

    public function getDhFunction(): DhFunction
    {
        return $this->dhFunction;
    }
}