<?php

namespace League\OAuth2\Client\Test;

use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;

final class KeyDumpSigner implements Signer
{
    public function algorithmId(): string
    {
        return 'keydump';
    }

    public function sign(string $payload, Key $key): string
    {
        return $key->contents();
    }

    public function verify(string $expected, string $payload, Key $key): bool
    {
        return $expected === $key->contents();
    }
}
