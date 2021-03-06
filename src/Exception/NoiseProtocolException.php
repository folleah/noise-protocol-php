<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol\Exception;

use Exception;

class NoiseProtocolException extends Exception
{
    public function __construct($message = "", ...$params)
    {
        parent::__construct(sprintf($message, ...$params));
    }
}