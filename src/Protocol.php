<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol;

use Invariance\NoiseProtocol\CipherFunction\CipherFunction;
use Invariance\NoiseProtocol\DhFunction\DhFunction;
use Invariance\NoiseProtocol\HashFunction\HashFunction;
use Invariance\NoiseProtocol\Internal\CipherState;
use Invariance\NoiseProtocol\Internal\HandshakeState;
use Invariance\NoiseProtocol\Internal\SymmetricState;
use Invariance\NoiseProtocol\Language\HandshakePattern;
use Invariance\NoiseProtocol\Language\PatternModifier;

class Protocol
{
    public const MAX_MESSAGE_LENGTH = 65535;

    /**
     * @var HandshakePattern
     */
    private $handshakePattern;

    /**
     * @var CipherFunction
     */
    private $cipherFunction;

    /**
     * @var HashFunction
     */
    private $hashFunction;

    /**
     * @var DhFunction
     */
    private $dhFunction;

    /**
     * @var string
     */
    private $protocolName;

    /**
     * @var CipherState
     */
    private $cipherState;

    /**
     * @var SymmetricState
     */
    private $symmetricState;

    public function __construct(
        string $handshakePattern,
        CipherFunction $cipherFunction,
        HashFunction $hashFunction,
        DhFunction $dhFunction,
        int $pskModifiers = PatternModifier::NONE
    ) {
        $this->protocolName = $this->generateProtocolName(
            $handshakePattern,
            (string)$dhFunction,
            (string)$cipherFunction,
            (string)$hashFunction
        );
        $this->handshakePattern = HandshakePattern::instantiate($handshakePattern);
        $this->cipherFunction = $cipherFunction;
        $this->hashFunction = $hashFunction;
        $this->dhFunction = $dhFunction;
        $this->cipherState = new CipherState($this);
        $this->symmetricState = new SymmetricState($this, $this->cipherState);
    }

    public function create(string $s): HandshakeState
    {
        return new HandshakeState(
            $this,
            $this->symmetricState
        );
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

    public function getName(): string
    {
        return $this->protocolName;
    }

    private function generateProtocolName(string $handshakePattern, string $dhFunction, string $cipherFunction, string $hashFunction): string
    {
        return sprintf('Noise_%s_%s_%s_%s', $handshakePattern, $dhFunction, $cipherFunction, $hashFunction);
    }
}