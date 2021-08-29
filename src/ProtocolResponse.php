<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol;

use Invariance\NoiseProtocol\Internal\CipherState;

class ProtocolResponse
{
    private string $data;
    private CipherState|null $cs1;
    private CipherState|null $cs2;

    public function __construct(string $data, CipherState|null $cs1 = null, CipherState|null $cs2 = null)
    {
        $this->data = $data;
        $this->cs1 = $cs1;
        $this->cs2 = $cs2;
    }

    public function getData(): string
    {
        return $this->data;
    }

    public function getCS1(): CipherState|null
    {
        return $this->cs1;
    }

    public function getCS2(): CipherState|null
    {
        return $this->cs2;
    }
}