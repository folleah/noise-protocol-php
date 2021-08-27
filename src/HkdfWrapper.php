<?php declare(strict_types=1);

namespace Invariance\NoiseProtocol;

use Invariance\NoiseProtocol\Exception\NoiseProtocolException;

final class HkdfWrapper
{
    /**
     * @param string $ck
     * @param string $inputKeyMaterial
     * @param int $numOutputs
     * @param int $hashLen
     * @param int $dhLen
     *
     * @return string - outputs
     */
    public static function generate(string $ck, string $inputKeyMaterial, int $numOutputs, int $hashLen, int $dhLen): string
    {
        $ckLength = strlen($ck);
        assert(
            $ckLength === $hashLen,
            new NoiseProtocolException('Invalid ck length: %s.', $ckLength)
        );

        $inputKeyMaterialLength = strlen($inputKeyMaterial);
        assert(
            $inputKeyMaterialLength === 0 || $inputKeyMaterialLength === 32 || $inputKeyMaterialLength === $dhLen,
            new NoiseProtocolException('Invalid input_key_material length: %s.', $inputKeyMaterialLength)
        );

        assert($numOutputs === 2 || $numOutputs === 3, new NoiseProtocolException('Invalid num outputs: %s', $numOutputs));
//
//        $tempKey = hash_hmac('sha256', $inputKeyMaterial, $ck, true);
//        $output1 = hash_hmac('sha256', pack('s*', 0x01), $tempKey, true);
//        $output2 = hash_hmac('sha256', $output1 . pack('s*', 0x02), $tempKey, true);
//
//        if ($numOutputs !== 3) {
//            return [$output1, $output2];
//        }
//
//        return [
//            $output1,
//            $output2,
//            hash_hmac('sha256', $output2 | pack('s*', 0x03), $tempKey, true)
//        ];

        return hash_hkdf('sha256', $ck, $hashLen * $numOutputs, '', $inputKeyMaterial);
    }
}