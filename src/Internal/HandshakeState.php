<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\Internal;

use Invariance\NoiseProtocol\Exception\NoiseProtocolException;
use Invariance\NoiseProtocol\KeyPair;
use Invariance\NoiseProtocol\Language\HandshakePattern;
use Invariance\NoiseProtocol\Language\MessagePattern;
use Invariance\NoiseProtocol\Language\Token;
use Invariance\NoiseProtocol\ProtocolConfig;
use Invariance\NoiseProtocol\ProtocolSuite;

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
     * @var \SplQueue|MessagePattern[]
     */
    private $messagePatterns;

    /**
     * @var ProtocolSuite
     */
    private $suite;

    /**
     * @var SymmetricState
     */
    private $symmetricState;

    /**
     * @throws NoiseProtocolException
     */
    public function __construct(ProtocolConfig $config)
    {
        $this->suite = $config->getSuite();
        $this->symmetricState = new SymmetricState(
            $this->suite,
            $config->getProtocolName()
        );

        $handshakePatternInstance = HandshakePattern::instantiate($config->getHandshakePattern());

//        if ($config->getS() !== null && strlen($config->getS()->getSecretKey()) !== $this->suite->getDhFunction()->getLen()) {
//            throw new NoiseProtocolException('Invalid local static private key.');
//        }
//
//        if ($config->getS() === null && $handshakePatternInstance->localRequired($config->isInitiator())) {
//            throw new NoiseProtocolException('Local static private key required, but not provided.');
//        }
//
//        if ($config->getS() !== null && !$handshakePatternInstance->localRequired($config->isInitiator())) {
//            throw new NoiseProtocolException('Local static private key provided, but not required.');
//        }
//
//        if ($config->getRs() !== null && strlen($config->getRs()) !== $this->suite->getDhFunction()->getLen()) {
//            throw new NoiseProtocolException('Invalid remote static public key.');
//        }
//
//        if ($config->getRs() === null && $handshakePatternInstance->remoteRequired($config->isInitiator())) {
//            throw new NoiseProtocolException('Remote static public key required, but not provided.');
//        }
//
//        if ($config->getRs() !== null && !$handshakePatternInstance->remoteRequired($config->isInitiator())) {
//            throw new NoiseProtocolException('Remote static public key provided, but not required.');
//        }
//
//        if ((protocol.Modifiers & PatternModifiers.Fallback) != 0)
//        {
//        throw new ArgumentException($"Fallback modifier can only be applied by calling the {nameof(Fallback)} method.");
//        }

        $this->symmetricState->mixHash($config->getPrologue());
        $this->messagePatterns = new \SplQueue();

        $this->initiator = $config->isInitiator();
        $this->s = $config->getS();
        $this->e = $config->getE();
        $this->rs = $config->getRs();
        $this->re = $config->getRe();

        $this->processPreMessages($handshakePatternInstance);
        foreach ($handshakePatternInstance->messagePatterns() as $pattern) {
            $this->messagePatterns->enqueue($pattern);
        }
    }

    /**
     * @param string $message
     * @param callable $output(string $messageBuffer, CipherState $c1, CipherState $c2)
     * @throws NoiseProtocolException
     */
    public function writeMessage(string $message, callable $output): void
    {
        if ($this->messagePatterns->count() === 0) {
            throw new NoiseProtocolException('Cannot call writeMessage after the handshake has already been completed.');
        }

        if (strlen($message) > ProtocolConfig::MAX_MESSAGE_LENGTH) {
            throw new NoiseProtocolException('Noise message must be less than or equal to %s bytes in length.', ProtocolConfig::MAX_MESSAGE_LENGTH);
        }

        $messageBuffer = '';
        /** @var MessagePattern $nextMsg */
        $nextMsg = $this->messagePatterns->dequeue();
        foreach ($nextMsg as $token) {
            switch ($token) {
                case Token::E:
                    $this->e = $this->suite->getDhFunction()->generateKeyPair();
                    $messageBuffer .= $this->e->getPublicKey();
                    $this->symmetricState->mixHash($this->e->getPublicKey());
                    break;
                case Token::S:
                    $messageBuffer .= $this->symmetricState->encryptAndHash($this->s->getPublicKey());
                    break;
                case Token::EE:
                    $this->symmetricState->mixKey(
                        $this->suite->getDhFunction()->dh($this->e, $this->re)
                    );
                    break;
                case Token::ES:
                    $this->symmetricState->mixKey(
                        $this->initiator
                            ? $this->suite->getDhFunction()->dh($this->e, $this->rs)
                            : $this->suite->getDhFunction()->dh($this->s, $this->re)
                    );
                    break;
                case Token::SE:
                    $this->symmetricState->mixKey(
                        $this->initiator
                            ? $this->suite->getDhFunction()->dh($this->s, $this->re)
                            : $this->suite->getDhFunction()->dh($this->e, $this->rs)
                    );
                    break;
                case Token::SS:
                    $this->symmetricState->mixKey(
                        $this->suite->getDhFunction()->dh($this->s, $this->rs)
                    );
                    break;
                default:
                    throw new NoiseProtocolException('Invalid message token %s.', $token);
            }
        }

        $messageBuffer .= $this->symmetricState->encryptAndHash($message);

        // if message patterns end, return new cipher states
        if ($this->messagePatterns->count() === 0) {
            $cStates = $this->symmetricState->split();
            $output($messageBuffer, $cStates[0], $cStates[1]);
        } else {
            $output($messageBuffer, null, null);
        }
    }

    public function readMessage(string $message, callable $output): void
    {
        if ($this->messagePatterns->count() === 0) {
            throw new NoiseProtocolException('Cannot call readMessage after the handshake has already been completed.');
        }

        if (strlen($message) > ProtocolConfig::MAX_MESSAGE_LENGTH) {
            throw new NoiseProtocolException('Noise message must be less than or equal to %s bytes in length.', ProtocolConfig::MAX_MESSAGE_LENGTH);
        }

        $handledBytes = 0;
        /** @var MessagePattern $nextMsg */
        $nextMsg = $this->messagePatterns->dequeue();
        foreach ($nextMsg as $token) {
            switch ($token) {
                case Token::E:
                    $readBytes = $this->suite->getDhFunction()->getLen();
                    $this->re = substr($message, $handledBytes, $readBytes);
                    $this->symmetricState->mixHash($this->re);
                    $handledBytes += $readBytes;
                    break;
                case Token::S:
                    $readBytes = $this->symmetricState->getCipherState()->hasKey()
                        ? $this->suite->getDhFunction()->getLen() + 16
                        : $this->suite->getDhFunction()->getLen();
                    $temp = substr($message, $handledBytes, $readBytes);
                    $this->rs = $this->symmetricState->decryptAndHash($temp);
                    $handledBytes += $readBytes;
                    break;
                case Token::EE:
                    $this->symmetricState->mixKey(
                        $this->suite->getDhFunction()->dh($this->e, $this->re)
                    );
                    break;
                case Token::ES:
                    $this->symmetricState->mixKey(
                        $this->initiator
                            ? $this->suite->getDhFunction()->dh($this->e, $this->rs)
                            : $this->suite->getDhFunction()->dh($this->s, $this->re)
                    );
                    break;
                case Token::SE:
                    $this->symmetricState->mixKey(
                        $this->initiator
                            ? $this->suite->getDhFunction()->dh($this->s, $this->re)
                            : $this->suite->getDhFunction()->dh($this->e, $this->rs)
                    );
                    break;
                case Token::SS:
                    $this->symmetricState->mixKey(
                        $this->suite->getDhFunction()->dh($this->s, $this->rs)
                    );
                    break;
                default:
                    throw new NoiseProtocolException('Invalid message token %s.', $token);
            }
        }

        $payloadBuffer = $this->symmetricState->decryptAndHash(
            substr($message, $handledBytes)
        );

        // if message patterns end, return new cipher states
        if ($this->messagePatterns->count() === 0) {
            $cStates = $this->symmetricState->split();
            $output($payloadBuffer, $cStates[0], $cStates[1]);
        } else {
            $output($payloadBuffer, null, null);
        }
    }

    private function processPreMessages(HandshakePattern $handshakePattern): void
    {
        foreach ($handshakePattern->initiator() as $token) {
            if ($token === Token::E) {
                $this->symmetricState->mixHash(
                    $this->initiator
                        ? $this->e->getPublicKey()
                        : $this->re
                );
            }

            if ($token === Token::S) {
                $this->symmetricState->mixHash(
                    $this->initiator
                        ? $this->s->getPublicKey()
                        : $this->rs
                );
            }
        }

        foreach ($handshakePattern->responder() as $token) {
            if ($token === Token::E) {
                $this->symmetricState->mixHash(
                    $this->initiator
                        ? $this->re
                        : $this->e->getPublicKey()
                );
            }

            if ($token === Token::S) {
                $this->symmetricState->mixHash(
                    $this->initiator
                        ? $this->rs
                        : $this->s->getPublicKey()
                );
            }
        }
    }
}