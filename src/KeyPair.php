<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol;

use Invariance\NoiseProtocol\DhFunction\Curve25519;
use Invariance\NoiseProtocol\DhFunction\DhFunction;

final class KeyPair
{
    private static DhFunction|null $dh = null;

    private string $secret;

    private string $public;

    public function __construct(string $secret, string $public)
    {
        $this->secret = $secret;
        $this->public = $public;
    }

    public static function generate(): self
    {
        if (self::$dh === null) {
            self::$dh = new Curve25519();
        }

        return self::$dh->generateKeyPair();
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