<?php

require '../vendor/autoload.php';

use Invariance\NoiseProtocol\CipherFunction\AesGcm;
use Invariance\NoiseProtocol\DhFunction\Curve25519;
use Invariance\NoiseProtocol\HashFunction\Sha256;
use Invariance\NoiseProtocol\Internal\HandshakeState;
use Invariance\NoiseProtocol\KeyPair;
use Invariance\NoiseProtocol\Language\HandshakePattern;
use Invariance\NoiseProtocol\ProtocolConfig;
use Invariance\NoiseProtocol\ProtocolSuite;

$suite = new ProtocolSuite(
    new AesGcm(),
    new Sha256(),
    new Curve25519()
);

$clientStatic = KeyPair::generate();
$serverStatic = KeyPair::generate();

$client = new HandshakeState(new ProtocolConfig(
    suite: $suite,
    handshakePattern: HandshakePattern::N,
    initiator: true,
    s: $clientStatic,
    rs: $serverStatic->getPublicKey()
));

$client->writeMessage('', function ($messageBuffer, $c1, $c2) {
    echo $messageBuffer;
});