<?php

namespace League\OAuth2\Client\Token;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use InvalidArgumentException;
use UnexpectedValueException;

class AppleAccessToken extends AccessToken
{
    /**
     * The issuer of every ID token signed by Apple
     */
    const ISSUER = 'https://appleid.apple.com';

    /**
     * @var string
     */
    protected $idToken;

    /**
     * @var string
     */
    protected $email;

    /**
     * @var boolean
     */
    protected $isPrivateEmail;

    /**
     * Constructs an access token.
     *
     * @param Key[] $keys Valid Apple JWT keys
     * @param array $options An array of options returned by the service provider
     *     in the access token request. The `access_token` option is required.
     * @param string|null $clientId The client ID (Services ID or Bundle ID) the ID token must be issued for.
     *     Without it the `aud` claim is not checked.
     * @throws InvalidArgumentException if `access_token` is not provided in `$options`.
     * @throws UnexpectedValueException if the ID token was not issued by Apple for this client.
     *
     * @throws \Exception
     */
    public function __construct(array $keys, array $options = [], $clientId = null)
    {
        if (array_key_exists('refresh_token', $options) && empty($options['id_token'])) {
            throw new InvalidArgumentException('Required option not passed: "id_token"');
        }

        // every ID token is verified, also without a refresh token (refresh grant, hand-built tokens)
        if (!empty($options['id_token'])) {
            // identity comes only from the signed ID token, never from the given options
            unset($options['resource_owner_id'], $options['email']);

            $decoded = null;
            $last = end($keys);
            foreach ($keys as $key) {
                try {
                    try {
                        $decoded = JWT::decode($options['id_token'], $key);
                    } catch (\UnexpectedValueException $e) {
                        $decodeMethodReflection = new \ReflectionMethod(JWT::class, 'decode');
                        $decodeMethodParameters = $decodeMethodReflection->getParameters();
                        // Backwards compatibility for firebase/php-jwt >=5.2.0 <=5.5.1 supported by PHP 5.6
                        if (array_key_exists(2, $decodeMethodParameters) &&
                            'allowed_algs' === $decodeMethodParameters[2]->getName()
                        ) {
                            $decoded = JWT::decode($options['id_token'], $key, ['RS256']);
                        } else {
                            $headers = (object) ['alg' => 'RS256'];
                            $decoded = JWT::decode($options['id_token'], $key, $headers);
                        }
                    }
                    break;
                } catch (\Exception $exception) {
                    if ($last === $key) {
                        throw $exception;
                    }
                }
            }
            if (null === $decoded) {
                throw new \Exception('Got no data within "id_token"!');
            }
            $payload = json_decode(json_encode($decoded), true);

            $this->validateClaims($payload, $clientId);

            $options['resource_owner_id'] = $payload['sub'];

            if (isset($payload['email']) && is_string($payload['email'])
                && isset($payload['email_verified']) && self::isTrue($payload['email_verified'])
            ) {
                $options['email'] = $payload['email'];
            }

            if (isset($payload['is_private_email'])) {
                $this->isPrivateEmail = self::isTrue($payload['is_private_email']);
            }
        }

        parent::__construct($options);

        if (isset($options['id_token'])) {
            $this->idToken = $options['id_token'];
        }

        if (isset($options['email'])) {
            $this->email = $options['email'];
        }
    }

    /**
     * The signature and the time claims (exp, iat, nbf) are already checked by JWT::decode().
     *
     * @param mixed $payload
     * @param string|null $clientId
     * @throws UnexpectedValueException
     */
    private function validateClaims($payload, $clientId)
    {
        if (!is_array($payload) || !isset($payload['iss']) || $payload['iss'] !== self::ISSUER) {
            throw new UnexpectedValueException('Invalid "iss" claim within "id_token"');
        }

        if (!isset($payload['sub']) || !is_string($payload['sub']) || $payload['sub'] === '') {
            throw new UnexpectedValueException('Missing "sub" claim within "id_token"');
        }

        if ($clientId === null) {
            return;
        }

        $audience = isset($payload['aud']) ? (array) $payload['aud'] : [];
        if (!in_array($clientId, $audience, true)) {
            throw new UnexpectedValueException('Invalid "aud" claim within "id_token"');
        }
    }

    /**
     * Apple sends some boolean claims as strings ("true" / "false")
     *
     * @param mixed $value
     * @return boolean
     */
    private static function isTrue($value)
    {
        return $value === true || $value === 'true';
    }

    /**
     * @return string
     */
    public function getIdToken()
    {
        return $this->idToken;
    }

    /**
     * @return string|null
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * @return boolean
     */
    public function isPrivateEmail()
    {
        return $this->isPrivateEmail;
    }
}
