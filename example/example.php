<?php

require '../vendor/autoload.php';

use Invariance\NoiseProtocol\CipherFunction\ChaChaPoly;
use Invariance\NoiseProtocol\DhFunction\Curve25519;
use Invariance\NoiseProtocol\DhFunction\Language\HandshakePattern;
use Invariance\NoiseProtocol\DhFunction\Language\PatternModifier;
use Invariance\NoiseProtocol\HashFunction\Sha512;
use Invariance\NoiseProtocol\Protocol;

$protocol = new Protocol(
    HandshakePattern::N(),
    new ChaChaPoly(),
    new Sha512(),
    new Curve25519()
);

$initiator = new HandshakeState(
    $protocol,
    true,
    'rs',
    PatternModifier::NONE
);