<?php

namespace League\OAuth2\Client\Test;

use Lcobucci\JWT\Signature;
use Lcobucci\JWT\Signer;

final class KeyDumpSigner implements Signer
{
    public function getAlgorithmId()
    {
        return 'keydump';
    }

    public function modifyHeader(array &$headers)
    {
        $headers['alg'] = $this->getAlgorithmId();
    }

    public function verify($expected, $payload, $key)
    {
        return $expected === $key->contents();
    }

    public function sign($payload, $key)
    {
        return new Signature($key->contents());
    }
}
