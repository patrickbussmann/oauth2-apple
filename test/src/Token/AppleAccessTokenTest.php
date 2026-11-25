<?php

namespace League\OAuth2\Client\Test\Token;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use League\OAuth2\Client\Token\AppleAccessToken;
use Mockery as m;
use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

class AppleAccessTokenTest extends TestCase
{
    #[PreserveGlobalState(false)]
    #[RunInSeparateProcess]
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

    #[PreserveGlobalState(false)]
    #[RunInSeparateProcess]
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

    private static ?\OpenSSLAsymmetricKey $signingKey = null;

    private static function signingKey(): \OpenSSLAsymmetricKey
    {
        return self::$signingKey ??= openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);
    }

    private static function appleKeys(): array
    {
        $public = openssl_pkey_get_details(self::signingKey())['key'];
        return ['test' => new Key($public, 'RS256')];
    }

    private static function tokenOptions(array $claims): array
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
            'id_token' => JWT::encode($claims, self::signingKey(), 'RS256', 'test'),
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
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid "iss" claim within "id_token"');

        new AppleAccessToken(self::appleKeys(), self::tokenOptions(['iss' => 'https://evil.example']), 'mock.example');
    }

    public function testIdTokenForOtherClientIsRejected()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid "aud" claim within "id_token"');

        new AppleAccessToken(self::appleKeys(), self::tokenOptions(['aud' => 'another.apple.client']), 'mock.example');
    }

    public function testExpiredIdTokenIsRejected()
    {
        $this->expectException(\Firebase\JWT\ExpiredException::class);

        new AppleAccessToken(self::appleKeys(), self::tokenOptions([
            'iat' => time() - 7200,
            'exp' => time() - 3600,
        ]), 'mock.example');
    }

    public function testMissingClientIdIsDeprecated()
    {
        $deprecation = null;
        set_error_handler(function (int $errno, string $errstr) use (&$deprecation) {
            $deprecation = $errstr;
            return true;
        }, E_USER_DEPRECATED);

        try {
            $token = new AppleAccessToken(self::appleKeys(), self::tokenOptions([]));
        } finally {
            restore_error_handler();
        }

        $this->assertEquals('123.abc.123', $token->getResourceOwnerId());
        $this->assertStringContainsString('client ID', $deprecation);
    }

    public function testUnverifiedEmailIsIgnored()
    {
        $token = new AppleAccessToken(self::appleKeys(), self::tokenOptions([
            'email' => 'john@doe.com',
            'email_verified' => 'false',
        ]), 'mock.example');

        $this->assertArrayNotHasKey('email', $token->getValues());
        $this->assertNull($token->getEmail());
        $this->assertFalse($token->isPrivateEmail());
    }

    public function testIdTokenWithoutRefreshTokenIsValidated()
    {
        $options = self::tokenOptions(['aud' => 'another.apple.client']);
        unset($options['refresh_token']);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid "aud" claim within "id_token"');

        new AppleAccessToken(self::appleKeys(), $options, 'mock.example');
    }

    public function testForgedIdTokenWithoutRefreshTokenIsRejected()
    {
        $forger = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        $claims = [
            'iss' => 'https://appleid.apple.com',
            'aud' => 'mock.example',
            'sub' => 'victim',
            'iat' => time(),
            'exp' => time() + 600,
        ];

        $this->expectException(\Firebase\JWT\SignatureInvalidException::class);

        new AppleAccessToken(self::appleKeys(), [
            'access_token' => 'access_token',
            'id_token' => JWT::encode($claims, $forger, 'RS256', 'test'),
            'resource_owner_id' => 'victim',
            'email' => 'victim@example.com',
        ], 'mock.example');
    }

    public function testIdentityFromOptionsIsIgnored()
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

    public function testExpiredIdTokenIsReportedWithSeveralKeys()
    {
        $other = openssl_pkey_get_details(openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]))['key'];

        $this->expectException(\Firebase\JWT\ExpiredException::class);

        new AppleAccessToken(self::appleKeys() + ['other' => new Key($other, 'RS256')], self::tokenOptions([
            'iat' => time() - 7200,
            'exp' => time() - 3600,
        ]), 'mock.example');
    }

    public function testNonStringEmailIsIgnored()
    {
        $token = new AppleAccessToken(self::appleKeys(), self::tokenOptions([
            'email' => ['john@doe.com'],
            'email_verified' => true,
        ]), 'mock.example');

        $this->assertArrayNotHasKey('email', $token->getValues());
        $this->assertNull($token->getEmail());
    }

    public function testNonStringSubIsRejected()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Missing "sub" claim within "id_token"');

        new AppleAccessToken(self::appleKeys(), self::tokenOptions(['sub' => ['123']]), 'mock.example');
    }
}
