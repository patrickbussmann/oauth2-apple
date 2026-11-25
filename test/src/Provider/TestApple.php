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
    private static ?string $localKey = null;

    /**
     * A P-256 key like the one Apple hands out, generated once per test run.
     *
     * {@inheritDoc}
     */
    public function getLocalKey(): string
    {
        if (self::$localKey === null) {
            $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
            openssl_pkey_export($key, $pem);
            self::$localKey = $pem;
        }

        return self::$localKey;
    }
}
