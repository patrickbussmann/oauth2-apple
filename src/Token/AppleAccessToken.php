<?php

namespace League\OAuth2\Client\Token;

use InvalidArgumentException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\JWT;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWS;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;

class AppleAccessToken extends AccessToken
{
    /**
     * @var string
     */
    protected $idToken;

    /**
     * @var string
     */
    protected $email;

    /**
     * Constructs an access token.
     *
     * @param array $options An array of options returned by the service provider
     *     in the access token request. The `access_token` option is required.
     * @throws InvalidArgumentException if `access_token` is not provided in `$options`.
     */
    public function __construct(array $options = [])
    {
        if (empty($options['id_token'])) {
            throw new InvalidArgumentException('Required option not passed: "id_token"');
        }

        $serializer = new CompactSerializer();
        $jws = $serializer->unserialize($options['id_token']);

        if (empty($options['id_token'])) {
            throw new InvalidArgumentException('Required option not passed: "id_token"');
        }

        $algorithmManager = new AlgorithmManager([new RS256()]);
        $jwsVerifier = new JWSVerifier($algorithmManager);
        $isVerified = $jwsVerifier->verifyWithKey($jws, $this->getAppleKey(), 0);

        if (!$isVerified) {
            throw new InvalidArgumentException('The token is not a valid one from Apple!');
        }

        $payload = json_decode($jws->getPayload(), true);

        $options['resource_owner_id'] = $payload['sub'];

        if (isset($payload['email_verified']) && $payload['email_verified']) {
            $options['email'] = $payload['email'];
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
     * @return \Jose\Component\Core\JWK Apple Key
     */
    protected function getAppleKey()
    {
        return JWKSet::createFromJson(file_get_contents('https://appleid.apple.com/auth/keys'))->get('AIDOPK1');
    }

    /**
     * @return string
     */
    public function getIdToken()
    {
        return $this->idToken;
    }

    /**
     * @return string
     */
    public function getEmail()
    {
        return $this->email;
    }
}
