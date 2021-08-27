<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\Internal;

use Invariance\NoiseProtocol\HkdfWrapper;
use Invariance\NoiseProtocol\Protocol;

class SymmetricState
{
    /**
     * @var string - A chaining key of HASHLEN bytes
     */
    private $ck;

    /**
     * @var string - A hash output of HASHLEN bytes
     */
    private $h;

    /**
     * @var CipherState
     */
    private $cipherState;

    /**
     * @var Protocol
     */
    private $protocol;

    public function __construct(Protocol $protocol, CipherState $cipherState)
    {
        $this->cipherState = $cipherState;
        $this->protocol = $protocol;
    }

    public function initializeSymmetric(string $protocolName): void
    {
        if (strlen($protocolName) <= $this->protocol->getHashFunction()->getHashLen()) {
            while (strlen($protocolName) < $this->protocol->getHashFunction()->getHashLen()) {
                $protocolName .= "\0";
            }

            $this->h = $protocolName;
        } else {
            $this->h = $this->protocol->getHashFunction()->hash($protocolName);
        }

        $this->ck = $this->h;

        $this->cipherState->initializeKey(null);
    }

    public function mixKey(string $inputKeyMaterial): void
    {
        $this->ck = $tempK = HkdfWrapper::generate(
            $this->ck,
            $inputKeyMaterial,
            2,
            $this->protocol->getHashFunction()->getHashLen(),
            $this->protocol->getDhFunction()->getLen()
        );

        if ($this->protocol->getHashFunction()->getHashLen() === 64) {
            $tempK = substr($tempK, 0, 32);
        }

        $this->cipherState->initializeKey($tempK);
    }

    public function mixHash(string $data): void
    {
        $this->h = $this->protocol->getHashFunction()->hash($this->h . $data);
    }

    public function mixKeyAndHash(string $inputMaterialKey): void
    {
        $this->ck = $tempH = $tempK = HkdfWrapper::generate(
            $this->ck,
            $inputMaterialKey,
            3,
            $this->protocol->getHashFunction()->getHashLen(),
            $this->protocol->getDhFunction()->getLen()
        );

        $this->mixHash($tempH);

        if ($this->protocol->getHashFunction()->getHashLen() === 64) {
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
        $cipherText = $this->cipherState->encryptWithAd($this->h, $plainText);
        $this->mixHash($cipherText);

        return $cipherText;
    }

    public function decryptAndHash(string $cipherText): string
    {
        $plainText = $this->cipherState->decryptWithAd($this->h, $cipherText);
        $this->mixHash($cipherText);

        return $plainText;
    }

    /**
     * @return CipherState[]
     */
    public function split(): array
    {
        $tempK1 = $tempK2 = HkdfWrapper::generate(
            $this->ck,
            '',
            2,
            $this->protocol->getHashFunction()->getHashLen(),
            $this->protocol->getDhFunction()->getLen()
        );

        if ($this->protocol->getHashFunction()->getHashLen() === 64) {
            $tempK1 = substr($tempK1, 0, 32);
            $tempK2 = substr($tempK2, 0, 32);
        }

        $c1 = new CipherState($this->protocol);
        $c1->initializeKey($tempK1);
        $c2 = new CipherState($this->protocol);
        $c2->initializeKey($tempK2);

        return [$c1, $c2];
    }
}