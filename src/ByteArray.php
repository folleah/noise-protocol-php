<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol;

class ByteArray implements \Iterator
{
    /** @var int */
    private $position = 0;

    /** @var \SplFixedArray|int[] */
    private $byteArray = [];

    public function __construct(int $length)
    {
        $this->byteArray = new \SplFixedArray($length);
    }

    public function place(string $str): void
    {
        foreach (str_split($str) as $chr) {
            $this->byteArray[] = ord($chr);
        }
    }

    public function __toString(): string
    {
        $res = new \SplFixedArray(count($this->byteArray));
        foreach ($this->byteArray as $k => $byte) {
            $res[$k] = chr($byte);
        }

        return implode('', $res);
    }

    public function toArray(): array
    {
        return $this->byteArray;
    }

    public function current(): int
    {
        return $this->byteArray[$this->position];
    }

    public function next(): void
    {
        ++$this->position;
    }

    public function key(): int
    {
        return $this->position;
    }

    public function valid(): bool
    {
        return isset($this->array[$this->position]);
    }

    public function rewind(): void
    {
        $this->position = 0;
    }
}