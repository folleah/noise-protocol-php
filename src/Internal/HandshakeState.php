<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\Internal;

use Invariance\NoiseProtocol\KeyPair;
use Invariance\NoiseProtocol\Language\HandshakePattern;
use Invariance\NoiseProtocol\Language\PatternModifier;
use Invariance\NoiseProtocol\Protocol;

class HandshakeState
{
    /**
     * @var KeyPair
     */
    private $s;

    /**
     * @var KeyPair
     */
    private $e;

    /**
     * @var string
     */
    private $rs;

    /**
     * @var string
     */
    private $re;

    /**
     * @var bool
     */
    private $initiator;

    /**
     * @var
     */
    private $messagePatterns;

    /**
     * @var Protocol
     */
    private $protocol;

    /**
     * @var SymmetricState
     */
    private $symmetricState;

    public function __construct(Protocol $protocol)
    {
        $this->protocol = $protocol;
        $this->symmetricState = new SymmetricState($protocol, new CipherState($protocol));
    }

    public function initialize(
        string  $handshakePattern,
        bool    $initiator,
        string  $prologue,
        KeyPair $s,
        KeyPair $e,
        string  $rs,
        string  $re
    ): void {
        $protocolName = $this->getProtocolName(
            $handshakePattern,
            (string)$this->protocol->getDhFunction(),
            (string)$this->protocol->getCipherFunction(),
            (string)$this->protocol->getHashFunction()
        );

        $this->symmetricState->initializeSymmetric($protocolName);
        $this->symmetricState->mixHash($prologue);

    }

    private function getProtocolName(string $handshakePattern, string $dhFunction, string $cipherFunction, string $hashFunction): string
    {
        return sprintf('Noise_%s_%s_%s_%s', $handshakePattern, $dhFunction, $cipherFunction, $hashFunction);
    }
}