<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol;

use Invariance\NoiseProtocol\Exception\NoiseProtocolException;
use Invariance\NoiseProtocol\HashFunction\HashFunction;

final class HkdfWrapper
{
    public static function generate(
        string $ck,
        string $inputKeyMaterial,
        int $numOutputs,
        HashFunction $hashFunc,
        int $dhLen,
        callable $output
    ): void {
        $ckLength = strlen($ck);
        assert(
            $ckLength === $hashFunc->getHashLen(),
            new NoiseProtocolException('Invalid ck length: %s.', $ckLength)
        );

        $inputKeyMaterialLength = strlen($inputKeyMaterial);
        assert(
            $inputKeyMaterialLength === 0 || $inputKeyMaterialLength === 32 || $inputKeyMaterialLength === $dhLen,
            new NoiseProtocolException('Invalid input_key_material length: %s.', $inputKeyMaterialLength)
        );

        assert($numOutputs === 2 || $numOutputs === 3, new NoiseProtocolException('Invalid num outputs: %s', $numOutputs));

//        var_dump(pack('s*', 0x01));die;
//        var_dump(hash_hmac('sha256', 'test', 'test', true));die;

        $tempKey = hash_hmac((string)$hashFunc, $inputKeyMaterial, $ck, true);
        $out1 = hash_hmac((string)$hashFunc, pack('s', 0x01), $tempKey, true);
        $out2 = hash_hmac((string)$hashFunc, $out1 . pack('s', 0x02), $tempKey, true);

        if ($numOutputs === 2) {
            $output($out1, $out2);
            return;
        }

        $out3 = hash_hmac((string)$hashFunc, $out2 . pack('s', 0x03), $tempKey, true);
        $output($out1, $out2, $out3);

//        return hash_hkdf('sha256', $ck, $hashLen * $numOutputs, '', $inputKeyMaterial);
    }
}