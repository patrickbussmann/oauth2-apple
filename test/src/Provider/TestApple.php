<?php

namespace League\OAuth2\Client\Test\Provider;

use League\OAuth2\Client\Provider\Apple;

/**
 * Class TestApple
 * @package League\OAuth2\Client\Test\Provider
 * @author Patrick Bußmann <patrick.bussmann@bussmann-it.de>
 */
class TestApple extends Apple
{
    /**
     * @return \Lcobucci\JWT\Signer\Key|null
     */
    public function getLocalKey()
    {
        return null;
    }
}
