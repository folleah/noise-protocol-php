<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol;

use Invariance\NoiseProtocol\CipherFunction\CipherFunction;
use Invariance\NoiseProtocol\DhFunction\DhFunction;
use Invariance\NoiseProtocol\DhFunction\Language\HandshakePattern;
use Invariance\NoiseProtocol\HashFunction\HashFunction;

class Protocol
{
    /** @var HandshakePattern */
    private $handshakePattern;

    /** @var CipherFunction */
    private $cipherFunction;

    /** @var HashFunction */
    private $hashFunction;

    /** @var DhFunction */
    private $dhFunction;

    public function __construct(
        HandshakePattern $handshakePattern,
        CipherFunction $cipherFunction,
        HashFunction $hashFunction,
        DhFunction $dhFunction
    ) {
        $this->handshakePattern = $handshakePattern;
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

    public function getHandshakePattern(): HandshakePattern
    {
        return $this->handshakePattern;
    }

    public function getModifiers(): int
    {

    }

    private function getProtocolName(): string
    {
        // Noise_${handshakePattern}_${dh.ALG}_${cipher.ALG}_${hash.ALG}`
        return sprintf('Noise_%s_%s_%s_%s', $this->handshakePattern->getName(), );
    }

    private function toCharCode(string $str): int
    {
        return ord($str);
    }
}