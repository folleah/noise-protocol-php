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

$initiatorKey = KeyPair::generate();
$responderKey = KeyPair::generate();

$initiator = new HandshakeState(new ProtocolConfig(
    suite: $suite,
    handshakePattern: HandshakePattern::XX,
    initiator: true,
    s: $initiatorKey
));

$responder = new HandshakeState(new ProtocolConfig(
    suite: $suite,
    handshakePattern: HandshakePattern::XX,
    initiator: false,
    s: $responderKey
));

echo '-> e:' . PHP_EOL;
$msg = $initiator->writeMessage('Hello!');
$res = $responder->readMessage($msg->getData());

echo 'MsgLen: ' . strlen($msg->getData()) . PHP_EOL;
echo 'ResLen: ' . strlen($res->getData()) . PHP_EOL;
echo 'Result: ' . $res->getData() . PHP_EOL . PHP_EOL;

echo '<- e, dhee, s, dhse:' . PHP_EOL;
$msg = $responder->writeMessage(null);
$res = $initiator->readMessage($msg->getData());
echo 'MsgLen: ' . strlen($msg->getData()) . PHP_EOL;
echo 'ResLen: ' . strlen($res->getData()) . PHP_EOL;
echo 'Result: ' . $res->getData() . PHP_EOL . PHP_EOL;

echo '-> s, dhse:' . PHP_EOL;
$payload = 'Test payload data 921831289751682943762839716298';
$msg = $initiator->writeMessage($payload);
$res = $responder->readMessage($msg->getData());
echo 'MsgLen: ' . strlen($msg->getData()) . PHP_EOL;
echo 'ResLen: ' . strlen($res->getData()) . PHP_EOL;
echo 'Result: ' . $res->getData() . PHP_EOL . PHP_EOL;

$csI1 = $msg->getCS1();
$csI2 = $msg->getCS2();
$csR1 = $res->getCS1();
$csR2 = $res->getCS2();

echo 'Transport message I -> R:' . PHP_EOL;
$msg = $csI1->encryptWithAd('Wubba');
$res = $csR1->decryptWithAd($msg);
echo 'Original: "Wubba"' . PHP_EOL;
echo 'Encrypted: ' . bin2hex($msg) . PHP_EOL;
echo 'Decrypted: ' . $res . PHP_EOL . PHP_EOL;

echo 'Transport message I -> R again:' . PHP_EOL;
$msg = $csI1->encryptWithAd('Lubba');
$res = $csR1->decryptWithAd($msg);
echo 'Original: "Lubba"' . PHP_EOL;
echo 'Encrypted: ' . bin2hex($msg) . PHP_EOL;
echo 'Decrypted: ' . $res . PHP_EOL . PHP_EOL;

echo 'Transport message R <- I:' . PHP_EOL;
$msg = $csI2->encryptWithAd('Dub dub!');
$res = $csR2->decryptWithAd($msg);
echo 'Original: "Dub dub!"' . PHP_EOL;
echo 'Encrypted: ' . bin2hex($msg) . PHP_EOL;
echo 'Decrypted: ' . $res . PHP_EOL . PHP_EOL;