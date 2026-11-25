<?php

declare(strict_types=1);

namespace League\OAuth2\Client\Token;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use InvalidArgumentException;
use UnexpectedValueException;

class AppleAccessToken extends AccessToken
{
    /* the issuer of every ID token signed by Apple */
    public const ISSUER = 'https://appleid.apple.com';

    protected string $idToken;

    protected string $email;

    protected bool $isPrivateEmail = false;

    /**
     * @var array
     */
    protected array $tokenPayload;

    /**
     * @param Key[] $keys Valid Apple JWT keys
     * @param array $options An array of options returned by the service provider
     *     in the access token request. The `access_token` option is required.
     * @param string|null $clientId The client ID (Services ID or Bundle ID) the ID token must be issued for.
     *     Will be required in a future major version.
     * @throws InvalidArgumentException if `access_token` is not provided in `$options`.
     * @throws UnexpectedValueException if the ID token was not issued by Apple for this client.
     *
     * @throws \Exception
     */
    public function __construct(array $keys, array $options = [], ?string $clientId = null)
    {
        if (array_key_exists('refresh_token', $options)) {
            if (empty($options['id_token'])) {
                throw new InvalidArgumentException('Required option not passed: "id_token"');
            }

            $decoded = null;
            $last = end($keys);
            foreach ($keys as $key) {
                try {
                    try {
                        $decoded = JWT::decode($options['id_token'], $key);
                    } catch (\UnexpectedValueException) {
                        $headers = (object) ['alg' => 'RS256'];
                        $decoded = JWT::decode($options['id_token'], $key, $headers);
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

            if (isset($payload['email']) && self::isTrue($payload['email_verified'] ?? false)) {
                $options['email'] = $payload['email'];
            }

            if (isset($payload['is_private_email'])) {
                $this->isPrivateEmail = self::isTrue($payload['is_private_email']);
            }

            $this->tokenPayload = $payload;
        }

        parent::__construct($options);

        if (isset($options['id_token'])) {
            $this->idToken = (string) $options['id_token'];
        }

        if (isset($options['email'])) {
            $this->email = (string) $options['email'];
        }
    }

    /**
     * The signature and the time claims (exp, iat, nbf) are already checked by JWT::decode().
     *
     * @throws UnexpectedValueException
     */
    private function validateClaims(array $payload, ?string $clientId): void
    {
        if (($payload['iss'] ?? null) !== self::ISSUER) {
            throw new UnexpectedValueException('Invalid "iss" claim within "id_token"');
        }

        if (empty($payload['sub'])) {
            throw new UnexpectedValueException('Missing "sub" claim within "id_token"');
        }

        if ($clientId === null) {
            trigger_error(
                'Creating an AppleAccessToken without a client ID skips the "aud" check'
                . ' and is deprecated. Pass the client ID as third argument.',
                E_USER_DEPRECATED
            );
            return;
        }

        if (!in_array($clientId, (array) ($payload['aud'] ?? []), true)) {
            throw new UnexpectedValueException('Invalid "aud" claim within "id_token"');
        }
    }

    /* Apple sends some boolean claims as strings ("true" / "false") */
    private static function isTrue(mixed $value): bool
    {
        return $value === true || $value === 'true';
    }

    public function getIdToken(): string
    {
        return $this->idToken;
    }

    public function getEmail(): string
    {
        return $this->email;
    }

    public function isPrivateEmail(): bool
    {
        return $this->isPrivateEmail;
    }

    /**
     * @return array
     */
    public function getTokenPayload(): array
    {
        return $this->tokenPayload;
    }
}
