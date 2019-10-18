<?php

namespace League\OAuth2\Client\Test\Provider;

use League\OAuth2\Client\Provider\Apple;
use League\OAuth2\Client\Tool\QueryBuilderTrait;
use Mockery as m;

class AppleTest extends \PHPUnit_Framework_TestCase
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
}
