<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\Internal;

use Invariance\NoiseProtocol\Exception\NoiseProtocolException;
use Invariance\NoiseProtocol\HkdfWrapper;
use Invariance\NoiseProtocol\ProtocolSuite;

final class SymmetricState
{
    /**
     * A chaining key of HASHLEN bytes
     */
    private string $ck;

    /**
     * A hash output of HASHLEN bytes
     */
    private string $h;

    private CipherState $cipherState;

    private ProtocolSuite $suite;

    public function __construct(ProtocolSuite $suite, string $protocolName)
    {
        $this->cipherState = new CipherState($suite);
        $this->suite = $suite;

        if (strlen($protocolName) <= $this->suite->getHashFunction()->getHashLen()) {
            while (strlen($protocolName) < $this->suite->getHashFunction()->getHashLen()) {
                $protocolName .= "\0";
            }

            $this->h = $protocolName;
        } else {
            $this->h = $this->suite->getHashFunction()->hash($protocolName);
        }

        $this->ck = $this->h;

        $this->cipherState->initializeKey(null);
    }

    public function mixKey(string $inputKeyMaterial): void
    {
        $tempK = null;
        HkdfWrapper::generate(
            $this->ck,
            $inputKeyMaterial,
            2,
            $this->suite->getHashFunction(),
            $this->suite->getDhFunction()->getLen(),
            function ($out1, $out2) use (&$tempK) {
                $this->ck = $out1;
                $tempK = $out2;
            }
        );

        if ($this->suite->getHashFunction()->getHashLen() === 64) {
            $tempK = substr($tempK, 0, 32);
        }

        $this->cipherState->initializeKey($tempK);
    }

    public function mixHash(string $data): void
    {
        $this->h = $this->suite->getHashFunction()->hash($this->h . $data);
    }

    public function mixKeyAndHash(string $inputMaterialKey): void
    {
        $tempH = null;
        $tempK = null;

        HkdfWrapper::generate(
            $this->ck,
            $inputMaterialKey,
            3,
            $this->suite->getHashFunction(),
            $this->suite->getDhFunction()->getLen(),
            function ($out1, $out2, $out3) use (&$tempH, &$tempK) {
                $this->ck = $out1;
                $tempH = $out2;
                $tempK = $out3;
            }
        );

        $this->mixHash($tempH);

        if ($this->suite->getHashFunction()->getHashLen() === 64) {
            $tempK = substr($tempK, 0, 32);
        }

        $this->cipherState->initializeKey($tempK);
    }

    public function getHandshakeHash(): string
    {
        return $this->h;
    }

    public function encryptAndHash(string $plainText): string
    {
        $cipherText = $this->cipherState->encryptWithAd($plainText, $this->h);
        $this->mixHash($cipherText);

        return $cipherText;
    }

    public function decryptAndHash(string $cipherText): string
    {
        $plainText = $this->cipherState->decryptWithAd($cipherText, $this->h);
        $this->mixHash($cipherText);

        return $plainText;
    }

    /**
     * @return CipherState[]
     * @throws NoiseProtocolException
     */
    public function split(): array
    {
        $tempK1 = null;
        $tempK2 = null;

        HkdfWrapper::generate(
            $this->ck,
            '',
            2,
            $this->suite->getHashFunction(),
            $this->suite->getDhFunction()->getLen(),
            function ($out1, $out2) use (&$tempK1, &$tempK2) {
                $tempK1 = $out1;
                $tempK2 = $out2;
            }
        );

        if ($this->suite->getHashFunction()->getHashLen() === 64) {
            $tempK1 = substr($tempK1, 0, 32);
            $tempK2 = substr($tempK2, 0, 32);
        }

        $c1 = new CipherState($this->suite);
        $c1->initializeKey($tempK1);
        $c2 = new CipherState($this->suite);
        $c2->initializeKey($tempK2);

        return [$c1, $c2];
    }

    public function getCipherState(): CipherState
    {
        return $this->cipherState;
    }
}