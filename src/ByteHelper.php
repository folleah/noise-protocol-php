<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol;

final class ByteHelper
{
    public static function intAlloc(int $value, int $length): string
    {
        $str = (string)$value;
        while (strlen($str) < $length) {
            $str .= "\0";
        }

        return $str;
    }
}