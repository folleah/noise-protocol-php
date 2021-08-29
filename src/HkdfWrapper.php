<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol;

use Invariance\NoiseProtocol\Exception\NoiseProtocolException;
use Invariance\NoiseProtocol\HashFunction\HashFunction;

final class HkdfWrapper
{
    public static function generate(
        string       $ck,
        string       $inputKeyMaterial,
        int          $numOutputs,
        HashFunction $hashFunc,
        int          $dhLen,
        callable     $output
    ): void
    {
        $ckLength = strlen($ck);
        if ($ckLength !== $hashFunc->getHashLen()) {
            throw new NoiseProtocolException('Invalid ck length: %s.', $ckLength);
        }

        $inputKeyMaterialLength = strlen($inputKeyMaterial);
        if ($inputKeyMaterialLength !== 0 && $inputKeyMaterialLength !== 32 && $inputKeyMaterialLength !== $dhLen) {
            throw new NoiseProtocolException('Invalid input_key_material length: %s.', $inputKeyMaterialLength);
        }

        if ($numOutputs !== 2 && $numOutputs !== 3) {
            throw new NoiseProtocolException('Invalid num outputs: %s', $numOutputs);
        }

        $tempKey = hash_hmac((string)$hashFunc, $inputKeyMaterial, $ck, true);
        $out1 = hash_hmac((string)$hashFunc, pack('s', 0x01), $tempKey, true);
        $out2 = hash_hmac((string)$hashFunc, $out1 . pack('s', 0x02), $tempKey, true);

        if ($numOutputs === 2) {
            $output($out1, $out2);
            return;
        }

        $out3 = hash_hmac((string)$hashFunc, $out2 . pack('s', 0x03), $tempKey, true);
        $output($out1, $out2, $out3);
    }
}