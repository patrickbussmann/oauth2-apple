<?php

namespace League\OAuth2\Client\Test\Provider;

use Exception;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Psr7\Response;
use InvalidArgumentException;
use Lcobucci\JWT\Builder;
use League\OAuth2\Client\Provider\Apple;
use League\OAuth2\Client\Test\Provider\TestApple;
use League\OAuth2\Client\Provider\AppleResourceOwner;
use League\OAuth2\Client\Provider\Exception\AppleAccessDeniedException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\QueryBuilderTrait;
use PHPUnit\Framework\TestCase;
use Mockery as m;

class AppleTest extends TestCase
{
    use QueryBuilderTrait;

	/** @var Apple|\Mockery\MockInterface */
    protected $provider;

    protected function setUp()
    {
        $this->provider = new \League\OAuth2\Client\Provider\Apple([
            'clientId' => 'mock.example',
            'teamId' => 'mock.team.id',
            'keyFileId' => 'mock.file.id',
            'keyFilePath' => __DIR__ . '/p256-private-key.p8',
            'redirectUri' => 'none'
        ]);
    }

    public function tearDown()
    {
        m::close();
        parent::tearDown();
    }

	/**
	 * @expectedException InvalidArgumentException
	 */
	public function testMissingTeamIdDuringInstantiationThrowsException()
	{
		new \League\OAuth2\Client\Provider\Apple([
			'clientId' => 'mock.example',
			'keyFileId' => 'mock.file.id',
			'keyFilePath' => __DIR__ . '/p256-private-key.p8',
			'redirectUri' => 'none'
		]);
	}

	/**
	 * @expectedException InvalidArgumentException
	 */
	public function testMissingKeyFileIdDuringInstantiationThrowsException()
	{
		new \League\OAuth2\Client\Provider\Apple([
			'clientId' => 'mock.example',
			'teamId' => 'mock.team.id',
			'keyFilePath' => __DIR__ . '/p256-private-key.p8',
			'redirectUri' => 'none'
		]);
	}

	/**
	 * @expectedException InvalidArgumentException
	 */
	public function testMissingKeyFilePathDuringInstantiationThrowsException()
	{
		new \League\OAuth2\Client\Provider\Apple([
			'clientId' => 'mock.example',
			'teamId' => 'mock.team.id',
			'keyFileId' => 'mock.file.id',
			'redirectUri' => 'none'
		]);
	}

	/**
	 * @expectedException InvalidArgumentException
	 */
	public function testMissingKeyDuringInstantiationThrowsException()
	{
		$this->provider->getLocalKey();
	}

    public function testAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('response_mode', $query);
        $this->assertNotNull($this->provider->getState());
    }

    public function testScopes()
    {
        $scopeSeparator = ' ';
        $options = ['scope' => [uniqid(), uniqid()]];
        $query = ['scope' => implode($scopeSeparator, $options['scope'])];
        $url = $this->provider->getAuthorizationUrl($options);
        $encodedScope = $this->buildQueryString($query);
        $this->assertContains($encodedScope, $url);
    }

    public function testGetAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);

        $this->assertEquals('/auth/authorize', $uri['path']);
    }

    public function testGetBaseAccessTokenUrl()
    {
        $params = [];

        $url = $this->provider->getBaseAccessTokenUrl($params);
        $uri = parse_url($url);

        $this->assertEquals('/auth/token', $uri['path']);
    }

	/**
	 * @expectedException \Firebase\JWT\SignatureInvalidException
	 */
    public function testGetAccessToken()
    {
	    $provider = new TestApple([
		    'clientId' => 'mock.example',
		    'teamId' => 'mock.team.id',
		    'keyFileId' => 'mock.file.id',
		    'keyFilePath' => __DIR__ . '/../../resources/p256-private-key.p8',
		    'redirectUri' => 'none'
	    ]);
        $provider = m::mock($provider);

	    $time = new \DateTimeImmutable();
        $expiresAt = $time->modify('+1 Hour');
	    $token = (new Builder())
		    ->issuedBy('test-team-id')
		    ->permittedFor('https://appleid.apple.com')
            ->issuedAt($time->getTimestamp())
            ->expiresAt($expiresAt->getTimestamp())
		    ->relatedTo('test-client')
		    ->withClaim('sub', 'test')
		    ->withHeader('alg', 'RS256')
		    ->withHeader('kid', 'test')
		    ->getToken();

	    $client = m::mock(ClientInterface::class);
	    $client->shouldReceive('request')
		    ->times(1)
		    ->andReturn(new Response(200, [], file_get_contents('https://appleid.apple.com/auth/keys')));
	    $client->shouldReceive('send')
		    ->times(1)
		    ->andReturn(new Response(200, [], json_encode([
			    'access_token' => 'aad897dee58fe4f66bf220c181adaf82b.0.mrwxq.hmiE0djj1vJqoNisKmF-pA',
			    'token_type' => 'Bearer',
			    'expires_in' => 3600,
			    'refresh_token' => 'r4a6e8b9c50104b78bc86b0d2649353fa.0.mrwxq.54joUj40j0cpuMANRtRjfg',
			    'id_token' => (string) $token
		    ])));
	    $provider->setHttpClient($client);

	    $provider->getAccessToken('authorization_code', [
    		'code' => 'hello-world'
	    ]);
    }

	public function testFetchingOwnerDetails()
	{
		$class = new \ReflectionClass($this->provider);
		$method = $class->getMethod('fetchResourceOwnerDetails');
		$method->setAccessible(true);

		$arr = [
			'name' => 'John Doe'
		];
		$_POST['user'] = json_encode($arr);
		$data = $method->invokeArgs($this->provider, [new AccessToken(['access_token' => 'hello'])]);

		$this->assertEquals($arr, $data);
	}

    /**
     * @see https://github.com/patrickbussmann/oauth2-apple/issues/12
     */
	public function testFetchingOwnerDetailsIssue12()
	{
		$class = new \ReflectionClass($this->provider);
		$method = $class->getMethod('fetchResourceOwnerDetails');
		$method->setAccessible(true);

        $_POST['user'] = '';
		$data = $method->invokeArgs($this->provider, [new AccessToken(['access_token' => 'hello'])]);

		$this->assertEquals([], $data);
	}

	/**
	 * @expectedException Exception
	 */
	public function testNotImplementedGetResourceOwnerDetailsUrl()
	{
		$this->provider->getResourceOwnerDetailsUrl(new AccessToken(['access_token' => 'hello']));
	}

    /**
     * @expectedException \League\OAuth2\Client\Provider\Exception\AppleAccessDeniedException
     */
	public function testCheckResponse()
	{
		$class = new \ReflectionClass($this->provider);
		$method = $class->getMethod('checkResponse');
		$method->setAccessible(true);

		$method->invokeArgs($this->provider, [new Response(400, []), [
			'error' => 'invalid_client',
			'code' => 400
		]]);
	}

	public function testCreationOfResourceOwner()
	{
		$class = new \ReflectionClass($this->provider);
		$method = $class->getMethod('createResourceOwner');
		$method->setAccessible(true);

		/** @var AppleResourceOwner $data */
		$data = $method->invokeArgs($this->provider, [
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
}
