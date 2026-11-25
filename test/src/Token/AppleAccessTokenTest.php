<?php

namespace League\OAuth2\Client\Test\Token;

use Firebase\JWT\Key;
use League\OAuth2\Client\Token\AppleAccessToken;
use PHPUnit\Framework\TestCase;
use Mockery as m;

class AppleAccessTokenTest extends TestCase
{
    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testCreatingAccessToken()
    {
        $externalJWTMock = m::mock('overload:Firebase\JWT\JWT');
        $externalJWTMock->shouldReceive('decode')
            ->with('something', 'examplekey')
            ->once()
            ->andReturn([
                'iss' => 'https://appleid.apple.com',
                'aud' => 'mock.example',
                'sub' => '123.abc.123',
                'email_verified' => true,
                'email' => 'john@doe.com',
                'is_private_email' => true
            ]);

        $accessToken = new AppleAccessToken(['examplekey'], [
            'access_token' => 'access_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'abc.0.def',
            'id_token' => 'something'
        ], 'mock.example');
        $this->assertEquals('something', $accessToken->getIdToken());
        $this->assertEquals('123.abc.123', $accessToken->getResourceOwnerId());
        $this->assertEquals('access_token', $accessToken->getToken());
        $this->assertEquals('john@doe.com', $accessToken->getEmail());
        $this->assertTrue($accessToken->isPrivateEmail());

        $this->assertTrue(true);
    }

    public function testCreateFailsBecauseNoIdTokenIsSet()
    {
        $this->expectException('\InvalidArgumentException');
        $this->expectExceptionMessage('Required option not passed: "id_token"');

        new AppleAccessToken(['examplekey'], [
            'access_token' => 'access_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'abc.0.def'
        ]);
    }

    public function testCreatingRefreshToken()
    {
        $refreshToken = new AppleAccessToken([], [
            'access_token' => 'access_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600
        ]);
        $this->assertEquals('access_token', $refreshToken->getToken());
    }

    /**
     * @runInSeparateProcess
     * @preserveGlobalState disabled
     */
    public function testCreatingAccessTokenFailsBecauseNoDecodingIsPossible()
    {
        $this->expectException('\Exception');
        $this->expectExceptionMessage('Got no data within "id_token"!');

        $externalJWTMock = m::mock('overload:Firebase\JWT\JWT');
        $externalJWTMock->shouldReceive('decode')
            ->with('something', 'examplekey')
            ->once()
            ->andReturnNull();

        new AppleAccessToken(['examplekey'], [
            'access_token' => 'access_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'abc.0.def',
            'id_token' => 'something'
        ]);
    }

    private static $privateKey;

    private static function privateKey()
    {
        if (self::$privateKey === null) {
            $key = openssl_pkey_new([
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
                'private_key_bits' => 2048,
            ]);
            openssl_pkey_export($key, $pem);
            self::$privateKey = $pem;
        }

        return self::$privateKey;
    }

    private static function appleKeys($privateKey = null)
    {
        $details = openssl_pkey_get_details(openssl_pkey_get_private($privateKey ?: self::privateKey()));

        // firebase/php-jwt < 5.5 has no Key class and takes the PEM string
        return ['test' => class_exists(Key::class) ? new Key($details['key'], 'RS256') : $details['key']];
    }

    private static function tokenOptions(array $claims, $privateKey = null)
    {
        $claims += [
            'iss' => 'https://appleid.apple.com',
            'aud' => 'mock.example',
            'sub' => '123.abc.123',
            'iat' => time(),
            'exp' => time() + 600,
        ];

        return [
            'access_token' => 'access_token',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => 'abc.0.def',
            'id_token' => \Firebase\JWT\JWT::encode($claims, $privateKey ?: self::privateKey(), 'RS256', 'test'),
        ];
    }

    public function testValidIdTokenIsAccepted()
    {
        $token = new AppleAccessToken(self::appleKeys(), self::tokenOptions([
            'email' => 'john@doe.com',
            'email_verified' => 'true',
            'is_private_email' => 'false',
        ]), 'mock.example');

        $this->assertEquals('123.abc.123', $token->getResourceOwnerId());
        $this->assertEquals('john@doe.com', $token->getEmail());
        $this->assertFalse($token->isPrivateEmail());
    }

    public function testAudienceAsArrayIsAccepted()
    {
        $token = new AppleAccessToken(self::appleKeys(), self::tokenOptions([
            'aud' => ['other.client', 'mock.example'],
        ]), 'mock.example');

        $this->assertEquals('123.abc.123', $token->getResourceOwnerId());
    }

    public function testIdTokenFromOtherIssuerIsRejected()
    {
        $this->expectException('\UnexpectedValueException');
        $this->expectExceptionMessage('Invalid "iss" claim within "id_token"');

        new AppleAccessToken(self::appleKeys(), self::tokenOptions(['iss' => 'https://evil.example']), 'mock.example');
    }

    public function testIdTokenForOtherClientIsRejected()
    {
        $this->expectException('\UnexpectedValueException');
        $this->expectExceptionMessage('Invalid "aud" claim within "id_token"');

        new AppleAccessToken(self::appleKeys(), self::tokenOptions(['aud' => 'another.apple.client']), 'mock.example');
    }

    public function testIdTokenWithoutRefreshTokenIsValidated()
    {
        $options = self::tokenOptions(['aud' => 'another.apple.client']);
        unset($options['refresh_token']);

        $this->expectException('\UnexpectedValueException');
        $this->expectExceptionMessage('Invalid "aud" claim within "id_token"');

        new AppleAccessToken(self::appleKeys(), $options, 'mock.example');
    }

    public function testForgedIdTokenWithoutRefreshTokenIsRejected()
    {
        $forger = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        openssl_pkey_export($forger, $forgerPem);
        $options = self::tokenOptions(['sub' => 'victim'], $forgerPem);
        unset($options['refresh_token']);

        $this->expectException('\Firebase\JWT\SignatureInvalidException');

        new AppleAccessToken(self::appleKeys(), $options + [
            'resource_owner_id' => 'victim',
            'email' => 'victim@example.com',
        ], 'mock.example');
    }

    public function testUnverifiedEmailAndIdentityFromOptionsAreIgnored()
    {
        $token = new AppleAccessToken(self::appleKeys(), self::tokenOptions([
            'email' => 'john@doe.com',
            'email_verified' => 'false',
        ]) + [
            'resource_owner_id' => 'victim',
            'email' => 'victim@example.com',
        ], 'mock.example');

        $this->assertEquals('123.abc.123', $token->getResourceOwnerId());
        $this->assertArrayNotHasKey('email', $token->getValues());
        $this->assertNull($token->getEmail());
    }

    public function testWithoutClientIdOnlyTheAudienceCheckIsSkipped()
    {
        $token = new AppleAccessToken(self::appleKeys(), self::tokenOptions(['aud' => 'another.apple.client']));
        $this->assertEquals('123.abc.123', $token->getResourceOwnerId());

        $this->expectException('\UnexpectedValueException');
        $this->expectExceptionMessage('Invalid "iss" claim within "id_token"');

        new AppleAccessToken(self::appleKeys(), self::tokenOptions(['iss' => 'https://evil.example']));
    }
}
