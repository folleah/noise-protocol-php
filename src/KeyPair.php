<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol;

class KeyPair
{
    /** @var string */
    private $secret;

    /** @var string */
    private $public;

    public function __construct(string $secret, string $public)
    {
        $this->secret = $secret;
        $this->public = $public;
    }

    public function getSecretKey(): string
    {
        return $this->secret;
    }

    public function getPublicKey(): string
    {
        return $this->public;
    }
}