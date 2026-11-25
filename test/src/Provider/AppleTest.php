<?php

declare(strict_types=1);

namespace League\OAuth2\Client\Test\Provider;

use Firebase\JWT\JWT;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Provider\Apple;
use League\OAuth2\Client\Provider\AppleResourceOwner;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AppleAccessToken;
use League\OAuth2\Client\Tool\QueryBuilderTrait;
use Mockery as m;
use PHPUnit\Framework\TestCase;

class AppleTest extends TestCase
{
    use QueryBuilderTrait;

    private function getProvider(): Apple
    {
        return new Apple([
            'clientId' => 'mock.example',
            'teamId' => 'mock.team.id',
            'keyFileId' => 'mock.file.id',
            'keyFilePath' => __DIR__ . '/p256-private-key.p8',
            'redirectUri' => 'none'
        ]);
    }

    public function testMissingTeamIdDuringInstantiationThrowsException()
    {
        $this->expectException('InvalidArgumentException');
        new Apple([
            'clientId' => 'mock.example',
            'keyFileId' => 'mock.file.id',
            'keyFilePath' => __DIR__ . '/p256-private-key.p8',
            'redirectUri' => 'none'
        ]);
    }

    public function testMissingKeyFileIdDuringInstantiationThrowsException()
    {
        $this->expectException('InvalidArgumentException');
        new Apple([
            'clientId' => 'mock.example',
            'teamId' => 'mock.team.id',
            'keyFilePath' => __DIR__ . '/p256-private-key.p8',
            'redirectUri' => 'none'
        ]);
    }

    public function testMissingKeyFilePathDuringInstantiationThrowsException()
    {
        $this->expectException('InvalidArgumentException');
        new Apple([
            'clientId' => 'mock.example',
            'teamId' => 'mock.team.id',
            'keyFileId' => 'mock.file.id',
            'redirectUri' => 'none'
        ]);
    }

    public function testMissingKeyDuringInstantiationThrowsException()
    {
        $this->expectException('InvalidArgumentException');
        $this->getProvider()->getLocalKey();
    }

    public function testAuthorizationUrl()
    {
        $provider = $this->getProvider();
        $url = $provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('response_mode', $query);
        $this->assertNotNull($provider->getState());
    }

    public function testScopes()
    {
        $provider = $this->getProvider();
        $scopeSeparator = ' ';
        $options = ['scope' => [uniqid(), uniqid()]];
        $query = ['scope' => implode($scopeSeparator, $options['scope'])];
        $url = $provider->getAuthorizationUrl($options);
        $encodedScope = $this->buildQueryString($query);
        $this->assertNotFalse(strpos($url, $encodedScope));
    }

    public function testGetAuthorizationUrl()
    {
        $provider = $this->getProvider();
        $url = $provider->getAuthorizationUrl();
        $uri = parse_url($url);

        $this->assertEquals('/auth/authorize', $uri['path']);
    }

    public function testGetBaseAccessTokenUrl()
    {
        $provider = $this->getProvider();
        $params = [];

        $url = $provider->getBaseAccessTokenUrl($params);
        $uri = parse_url($url);

        $this->assertEquals('/auth/token', $uri['path']);
    }

    private function getTestProvider(): TestApple
    {
        return new TestApple([
            'clientId' => 'mock.example',
            'teamId' => 'mock.team.id',
            'keyFileId' => 'mock.file.id',
            'keyFilePath' => dirname(__DIR__, 2) . '/resources/p256-private-key.p8',
            'redirectUri' => 'none'
        ]);
    }

    /**
     * Mocks Apple: the key set of a fresh RSA key and a token response with an ID token signed by it.
     */
    private function mockAppleClient(array $claims): ClientInterface
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
        $rsa = openssl_pkey_get_details($key)['rsa'];
        $base64Url = static fn (string $raw): string => rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
        $keySet = ['keys' => [[
            'kty' => 'RSA',
            'kid' => 'test',
            'use' => 'sig',
            'alg' => 'RS256',
            'n' => $base64Url($rsa['n']),
            'e' => $base64Url($rsa['e']),
        ]]];

        $time = time();
        $idToken = JWT::encode($claims + [
            'iss' => 'https://appleid.apple.com',
            'aud' => 'mock.example',
            'sub' => '123.abc.123',
            'iat' => $time,
            'exp' => $time + 600,
        ], $key, 'RS256', 'test');

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('request')
            ->times(1)
            ->andReturn(new Response(200, [], json_encode($keySet)));
        $client->shouldReceive('send')
            ->times(1)
            ->andReturn(new Response(200, [], json_encode([
                'access_token' => 'aad897dee58fe4f66bf220c181adaf82b.0.mrwxq.hmiE0djj1vJqoNisKmF-pA',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'refresh_token' => 'r4a6e8b9c50104b78bc86b0d2649353fa.0.mrwxq.54joUj40j0cpuMANRtRjfg',
                'id_token' => $idToken
            ])));

        return $client;
    }

    public function testGetAccessToken()
    {
        $provider = $this->getTestProvider();
        $provider->setHttpClient($this->mockAppleClient([
            'email' => 'john@doe.com',
            'email_verified' => 'true',
            'is_private_email' => 'false',
        ]));

        $token = $provider->getAccessToken('authorization_code', [
            'code' => 'hello-world'
        ]);

        $this->assertInstanceOf(AppleAccessToken::class, $token);
        $this->assertEquals('123.abc.123', $token->getResourceOwnerId());
        $this->assertEquals('john@doe.com', $token->getEmail());
        $this->assertFalse($token->isPrivateEmail());
    }

    /**
     * The provider must pass its client ID on, so an ID token issued for another app is rejected.
     */
    public function testGetAccessTokenRejectsIdTokenForOtherClient()
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid "aud" claim within "id_token"');

        $provider = $this->getTestProvider();
        $provider->setHttpClient($this->mockAppleClient(['aud' => 'another.apple.client']));

        $provider->getAccessToken('authorization_code', [
            'code' => 'hello-world'
        ]);
    }

    public function testGetAccessTokenFailedBecauseAppleHasError()
    {
        $this->expectException('Exception');
        $this->expectExceptionMessage('Got no data within "id_token"!');

        $provider = new TestApple([
            'clientId' => 'mock.example',
            'teamId' => 'mock.team.id',
            'keyFileId' => 'mock.file.id',
            'keyFilePath' => dirname(__DIR__, 2) . '/resources/p256-private-key.p8',
            'redirectUri' => 'none'
        ]);
        $provider = m::mock($provider);

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('request')
            ->times(1)
            ->andReturn(new Response(500, [], 'Internal Server Error'));
        $client->shouldReceive('send')
            ->times(1)
            ->andReturn(new Response(200, [], json_encode([
                'access_token' => 'aad897dee58fe4f66bf220c181adaf82b.0.mrwxq.hmiE0djj1vJqoNisKmF-pA',
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                'refresh_token' => 'r4a6e8b9c50104b78bc86b0d2649353fa.0.mrwxq.54joUj40j0cpuMANRtRjfg',
                'id_token' => 'abc'
            ])));
        $provider->setHttpClient($client);

        $provider->getAccessToken('authorization_code', [
            'code' => 'hello-world'
        ]);
    }

    public function testRevokeAccessToken()
    {
        $provider = new TestApple([
            'clientId' => 'mock.example',
            'teamId' => 'mock.team.id',
            'keyFileId' => 'mock.file.id',
            'keyFilePath' => dirname(__DIR__, 2) . '/resources/p256-private-key.p8',
            'redirectUri' => 'none'
        ]);
        $provider = m::mock($provider);

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('send')
            ->times(1)
            ->andReturn(new Response(200, [], json_encode([])));
        $provider->setHttpClient($client);

        $this->assertEmpty($provider->revokeAccessToken('hello-world', 'access_token'));
    }

    public function testRevokeAccessTokenFailedBecauseAppleHasError()
    {
        $this->expectException('Exception');
        $this->expectExceptionMessage('invalid_request');

        $provider = new TestApple([
            'clientId' => 'mock.example',
            'teamId' => 'mock.team.id',
            'keyFileId' => 'mock.file.id',
            'keyFilePath' => dirname(__DIR__, 2) . '/resources/p256-private-key.p8',
            'redirectUri' => 'none'
        ]);
        $provider = m::mock($provider);

        $client = m::mock(ClientInterface::class);
        $client->shouldReceive('send')
            ->times(1)
            ->andReturn(new Response(400, [], json_encode(['error' => 'invalid_request'])));
        $provider->setHttpClient($client);

        $provider->revokeAccessToken('hello-world');
    }

    public function testFetchingOwnerDetails()
    {
        $provider = $this->getProvider();
        $class = new \ReflectionClass($provider);
        $method = $class->getMethod('fetchResourceOwnerDetails');
        $method->setAccessible(true);

        $arr = [
            'name' => 'John Doe'
        ];
        $_POST['user'] = json_encode($arr);
        $data = $method->invokeArgs($provider, [new AccessToken(['access_token' => 'hello'])]);

        $this->assertEquals($arr, $data);
    }

    /**
     * @see https://github.com/patrickbussmann/oauth2-apple/issues/12
     */
    public function testFetchingOwnerDetailsIssue12()
    {
        $provider = $this->getProvider();
        $class = new \ReflectionClass($provider);
        $method = $class->getMethod('fetchResourceOwnerDetails');
        $method->setAccessible(true);

        $_POST['user'] = '';
        $data = $method->invokeArgs($provider, [new AccessToken(['access_token' => 'hello'])]);

        $this->assertEquals([], $data);
    }

    /**
     * The "user" field is user input, so anything but a JSON object must be ignored.
     */
    public function testFetchingOwnerDetailsIgnoresMalformedUserField()
    {
        $provider = $this->getProvider();
        $method = (new \ReflectionClass($provider))->getMethod('fetchResourceOwnerDetails');
        $method->setAccessible(true);
        $token = new AccessToken(['access_token' => 'hello']);

        foreach (['5', '"abc"', 'true', ['name' => 'John']] as $user) {
            $_POST['user'] = $user;
            $this->assertSame([], $method->invokeArgs($provider, [$token]));
        }
        unset($_POST['user']);
    }

    public function testMalformedNameIsIgnored()
    {
        $provider = $this->getProvider();
        $method = (new \ReflectionClass($provider))->getMethod('createResourceOwner');
        $method->setAccessible(true);

        /** @var AppleResourceOwner $data */
        $data = $method->invokeArgs($provider, [
            ['name' => ['firstName' => ['John']]],
            new AccessToken(['access_token' => 'hello', 'resource_owner_id' => '123.4.567'])
        ]);

        $this->assertNull($data->getFirstName());
        $this->assertNull($data->getLastName());
    }

    public function testNotImplementedGetResourceOwnerDetailsUrl()
    {
        $this->expectException('Exception');
        $provider = $this->getProvider();
        $provider->getResourceOwnerDetailsUrl(new AccessToken(['access_token' => 'hello']));
    }

    public function testCheckResponse()
    {
        $this->expectException('\League\OAuth2\Client\Provider\Exception\AppleAccessDeniedException');
        $this->expectExceptionMessage('invalid_client');
        $provider = $this->getProvider();
        $class = new \ReflectionClass($provider);
        $method = $class->getMethod('checkResponse');
        $method->setAccessible(true);

        $method->invokeArgs($provider, [new Response(400, []), [
            'error' => 'invalid_client',
            'code' => 400
        ]]);
    }

    public function testResourceToArrayHasAttributes()
    {
        $provider = $this->getProvider();
        $class = new \ReflectionClass($provider);
        $method = $class->getMethod('createResourceOwner');
        $method->setAccessible(true);

        /** @var AppleResourceOwner $data */
        $data = $method->invokeArgs($provider, [
            [
                'email' => 'john@doe.com',// <- Fake E-Mail from user input
                'name' => [
                    'firstName' => 'John',
                    'lastName' => 'Doe'
                ]
            ],
            new AccessToken([
                'access_token' => 'hello',
                'email' => 'john@doe.de',
                'resource_owner_id' => '123.4.567'
            ])
        ]);
        $expectedArray = [
            'email' => 'john@doe.de',
            'sub' => '123.4.567',
            'name' => [
                'firstName' => 'John',
                'lastName' => 'Doe'
            ],
            'isPrivateEmail' => null
        ];
        $this->assertEquals($expectedArray, $data->toArray());
    }

    public function testCreationOfResourceOwnerWithName()
    {
        $provider = $this->getProvider();
        $class = new \ReflectionClass($provider);
        $method = $class->getMethod('createResourceOwner');
        $method->setAccessible(true);

        /** @var AppleResourceOwner $data */
        $data = $method->invokeArgs($provider, [
            [
                'email' => 'john@doe.com',// <- Fake E-Mail from user input
                'name' => [
                    'firstName' => 'John',
                    'lastName' => 'Doe'
                ]
            ],
            new AccessToken([
                'access_token' => 'hello',
                'email' => 'john@doe.de',
                'resource_owner_id' => '123.4.567'
            ])
        ]);
        $this->assertEquals('john@doe.de', $data->getEmail());
        $this->assertEquals('Doe', $data->getLastName());
        $this->assertEquals('John', $data->getFirstName());
        $this->assertEquals('123.4.567', $data->getId());
        $this->assertFalse($data->isPrivateEmail());
        $this->assertArrayHasKey('name', $data->toArray());
    }

    public function testCreationOfResourceOwnerWithoutName()
    {
        $provider = $this->getProvider();
        $class = new \ReflectionClass($provider);
        $method = $class->getMethod('createResourceOwner');
        $method->setAccessible(true);

        /** @var AppleResourceOwner $data */
        $data = $method->invokeArgs($provider, [
            [],
            new AccessToken([
                'access_token' => 'hello',
                'email' => 'john@doe.de',
                'resource_owner_id' => '123.4.567'
            ])
        ]);
        $this->assertEquals('john@doe.de', $data->getEmail());
        $this->assertNull($data->getLastName());
        $this->assertNull($data->getFirstName());
    }

    /**
     * The "user" field is not signed, so its email must never end up as the resource owner email.
     */
    public function testEmailFromUserFieldIsIgnored()
    {
        $provider = $this->getProvider();
        $class = new \ReflectionClass($provider);
        $method = $class->getMethod('createResourceOwner');
        $method->setAccessible(true);

        /** @var AppleResourceOwner $data */
        $data = $method->invokeArgs($provider, [
            [
                'sub' => 'victim.sub',
                'email' => 'victim@example.com',
                'name' => [
                    'firstName' => 'John',
                    'lastName' => 'Doe'
                ]
            ],
            new AccessToken([
                'access_token' => 'hello',
                'resource_owner_id' => '123.4.567'
            ])
        ]);

        $this->assertNull($data->getEmail());
        $this->assertEquals('123.4.567', $data->getId());
        $this->assertEquals('123.4.567', $data->toArray()['sub']);
        $this->assertEquals('John', $data->getFirstName());
    }
}
