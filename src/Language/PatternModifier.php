<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\Language;

class PatternModifier
{
    public const NONE = 0;
    public const FALLBACK = 1;
    public const PSK0 = 2;
    public const PSK1 = 4;
    public const PSK2 = 8;
    public const PSK3 = 16;
}