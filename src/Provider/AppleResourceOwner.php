<?php

declare(strict_types=1);

namespace League\OAuth2\Client\Provider;

use League\OAuth2\Client\Tool\ArrayAccessorTrait;

class AppleResourceOwner extends GenericResourceOwner
{
    use ArrayAccessorTrait;

    protected $response = [];

    private ?string $email;

    /* true when it's a private relay from apple else the user mail address */
    private bool $isPrivateEmail;

    /**
     * Gets resource owner attribute by key. The key supports dot notation.
     */
    public function getAttribute(string $key): mixed
    {
        return $this->getValueByKey($this->response, $key);
    }

    public function getFirstName(): ?string
    {
        return $this->getNamePart('firstName');
    }

    /**
     * @inheritDoc
     */
    public function getId()
    {
        return $this->resourceOwnerId;
    }

    public function getLastName(): ?string
    {
        return $this->getNamePart('lastName');
    }

    public function getEmail(): ?string
    {
        return $this->getAttribute('email');
    }

    /* the name comes from the unsigned "user" field, so its shape is not guaranteed */
    private function getNamePart(string $key): ?string
    {
        $name = $this->getAttribute('name');
        $part = is_array($name) ? ($name[$key] ?? null) : null;

        return is_string($part) ? $part : null;
    }

    public function isPrivateEmail(): bool
    {
        return (bool) $this->getAttribute('isPrivateEmail');
    }

    /**
     * @inheritDoc
     */
    public function toArray(): array
    {
        return $this->response;
    }
}
