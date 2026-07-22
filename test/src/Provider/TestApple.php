<?php

namespace League\OAuth2\Client\Test\Provider;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use League\OAuth2\Client\Provider\Apple;
use League\OAuth2\Client\Test\KeyDumpSigner;

/**
 * Class TestApple
 * @package League\OAuth2\Client\Test\Provider
 * @author Patrick Bußmann <patrick.bussmann@bussmann-it.de>
 */

class TestApple extends Apple
{
    /**
     * {@inheritDoc}
     */
    public function getLocalKey(): string
    {
        return 'file://' . __DIR__ . '/../private_key.pem';
    }
}
