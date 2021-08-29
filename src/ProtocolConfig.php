<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol;

use Invariance\NoiseProtocol\Language\PatternModifier;
use JetBrains\PhpStorm\Pure;

final class ProtocolConfig
{
    public const MAX_MESSAGE_LENGTH = 65535;

    private ProtocolSuite $suite;

    private string $handshakePattern;

    private bool $initiator;

    private string $prologue;

    private KeyPair|null $s;

    private KeyPair|null $e;

    private string|null $rs;

    private string|null $re;

    private int $psks;

    public function __construct(
        ProtocolSuite  $suite,
        string         $handshakePattern,
        bool           $initiator,
        ?KeyPair       $s = null,
        ?KeyPair       $e = null,
        ?string        $rs = null,
        ?string        $re = null,
        string         $prologue = '',
        int            $psks = PatternModifier::NONE
    ) {
        $this->suite = $suite;
        $this->handshakePattern = $handshakePattern;
        $this->initiator = $initiator;
        $this->prologue = $prologue;
        $this->s = $s;
        $this->e = $e;
        $this->rs = $rs;
        $this->re = $re;
        $this->psks = $psks;
    }

    public function getSuite(): ProtocolSuite
    {
        return $this->suite;
    }

    public function getHandshakePattern(): string
    {
        return $this->handshakePattern;
    }

    public function isInitiator(): bool
    {
        return $this->initiator;
    }

    public function getPrologue(): string
    {
        return $this->prologue;
    }

    public function getS(): ?KeyPair
    {
        return $this->s;
    }

    public function getE(): ?KeyPair
    {
        return $this->e;
    }

    public function getRs(): ?string
    {
        return $this->rs;
    }

    public function getRe(): ?string
    {
        return $this->re;
    }

    public function getPsks(): int
    {
        return $this->psks;
    }

    #[Pure] public function getProtocolName(): string
    {
        return sprintf(
            'Noise_%s_%s_%s_%s',
            $this->handshakePattern,
            (string)$this->suite->getDhFunction(),
            (string)$this->suite->getCipherFunction(),
            (string)$this->suite->getHashFunction()
        );
    }
}