<?php

declare(strict_types=1);

namespace League\OAuth2\Client\Provider;

use Exception;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use InvalidArgumentException;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Provider\Exception\AppleAccessDeniedException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Token\AccessTokenInterface;
use League\OAuth2\Client\Token\AppleAccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class Apple extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * Default scopes
     *
     * @var array<string>
     */
    public array $defaultScopes = ['name', 'email'];

    /* the team id */
    protected string $teamId;

    /* the key file id */
    protected string $keyFileId;

    /* the key file path */
    protected $keyFilePath;

    /**
     * @inheritDoc
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        if (empty($options['teamId'])) {
            throw new InvalidArgumentException('Required option not passed: "teamId"');
        }

        if (empty($options['keyFileId'])) {
            throw new InvalidArgumentException('Required option not passed: "keyFileId"');
        }

        if (empty($options['keyFilePath'])) {
            throw new InvalidArgumentException('Required option not passed: "keyFilePath"');
        }

        parent::__construct($options, $collaborators);
    }

    /**
     * @inheritDoc
     */
    protected function createAccessToken(array $response, AbstractGrant $grant): AccessTokenInterface
    {
        return new AppleAccessToken($this->getAppleKeys(), $response);
    }

    /**
     * @return array<string, Key> Apple's JSON Web Keys
     * @throws GuzzleException
     */
    private function getAppleKeys(): array
    {
        $response = $this->httpClient->request('GET', 'https://appleid.apple.com/auth/keys');

        if ($response->getStatusCode() === 200) {
            return JWK::parseKeySet(json_decode($response->getBody()->__toString(), true));
        }

        return [];
    }

    /**
     * @inheritDoc
     */
    protected function getScopeSeparator(): string
    {
        return ' ';
    }

    /**
     * @inheritDoc
     */
    protected function getAuthorizationParameters(array $options): array
    {
        $options = parent::getAuthorizationParameters($options);
        if (str_contains($options['scope'], 'name') || str_contains($options['scope'], 'email')) {
            $options['response_mode'] = 'form_post';
        }
        return $options;
    }

    /**
     * @inheritDoc
     */
    protected function fetchResourceOwnerDetails(AccessToken $token)
    {
        return json_decode(array_key_exists('user', $_GET) ? $_GET['user']
            : (array_key_exists('user', $_POST) ? $_POST['user'] : '[]'), true) ?: [];
    }

    /**
     * @inheritDoc
     */
    public function getBaseAuthorizationUrl(): string
    {
        return 'https://appleid.apple.com/auth/authorize';
    }

    /**
     * @inheritDoc
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return 'https://appleid.apple.com/auth/token';
    }

    /* Get revoke token url to revoke token */
    public function getBaseRevokeTokenUrl(): string
    {
        return 'https://appleid.apple.com/auth/revoke';
    }

    /**
     * Get provider url to fetch user details
     *
     * @inheritDoc
     * @throws Exception
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        throw new Exception('No Apple ID REST API available yet!');
    }

    /**
     * @inheritDoc
     */
    protected function getDefaultScopes(): array
    {
        return $this->defaultScopes;
    }

    /**
     * Check a provider response for errors.
     *
     * @inheritDoc
     * @throws AppleAccessDeniedException
     */
    protected function checkResponse(ResponseInterface $response, $data): void
    {
        if ($response->getStatusCode() >= 400) {
            $message = $response->getReasonPhrase();
            if (array_key_exists('error', $data)) {
                $message = $data['error'];
            }
            if (array_key_exists('error_description', $data)) {
                $message .= ': ' . $data['error_description'];
            }
            throw new AppleAccessDeniedException(
                $message,
                array_key_exists('code', $data) ? $data['code'] : $response->getStatusCode(),
                $response
            );
        }
    }

    /**
     * Generate a user object from a successful user details request.
     *
     * @inheritDoc
     */
    protected function createResourceOwner(array $response, AccessToken $token): AppleResourceOwner
    {
        return new AppleResourceOwner(
            array_merge(
                ['sub' => $token->getResourceOwnerId()],
                $response,
                [
                    'email' => $token->getValues()['email'] ?? ($response['email'] ?? null),
                    'isPrivateEmail' => $token instanceof AppleAccessToken ? $token->isPrivateEmail() : null
                ]
            ),
            $token->getResourceOwnerId()
        );
    }

    /**
     * {@inheritDoc}
     */
    public function getAccessToken($grant, array $options = []): AccessTokenInterface
    {
        $time = time();

        $payload = [
            'iss' => $this->teamId,
            'iat' => $time,
            'exp' => $time + 3600,
            'aud' => 'https://appleid.apple.com',
            'sub' => $this->clientId,
        ];

        $jwt = JWT::encode(
            $payload,
            $this->getLocalKey(),
            'ES256',
            $this->keyFileId,
            [
                'kid' => $this->keyFileId,
                'alg' => 'ES256',
            ]
        );

        $options += [
            'client_secret' => $jwt
        ];

        return parent::getAccessToken($grant, $options);
    }

    /* Revokes an access or refresh token using a specified token. */
    public function revokeAccessToken(string $token, ?string $tokenTypeHint = null)
    {
        $time = time();

        $payload = [
            'iss' => $this->teamId,
            'iat' => $time,
            'exp' => $time + 3600,
            'aud' => 'https://appleid.apple.com',
            'sub' => $this->clientId,
        ];

        $clientSecret = JWT::encode(
            $payload,
            $this->getLocalKey(),
            'ES256',
            $this->keyFileId,
            [
                'kid' => $this->keyFileId,
                'alg' => 'ES256',
            ]
        );

        $params = [
            'client_id' => $this->clientId,
            'client_secret' => $clientSecret,
            'token' => $token
        ];

        if ($tokenTypeHint !== null) {
            $params += [
                'token_type_hint' => $tokenTypeHint
            ];
        }

        $method = $this->getAccessTokenMethod();
        $url = $this->getBaseRevokeTokenUrl();
        if (property_exists($this, 'optionProvider')) {
            $options = $this->optionProvider->getAccessTokenOptions(self::METHOD_POST, $params);
        } else {
            $options = $this->getAccessTokenOptions($params);
        }
        $request = $this->getRequest($method, $url, $options);

        return $this->getParsedResponse($request);
    }

    public function getLocalKey(): string
    {
        if (!file_exists($this->keyFilePath)) {
            throw new \InvalidArgumentException('Could not read key file');
        }

        return file_get_contents($this->keyFilePath);
    }
}
