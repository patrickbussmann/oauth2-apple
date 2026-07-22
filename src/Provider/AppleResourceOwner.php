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
        $name = $this->getAttribute('name');
        if (is_array($name)) {
            return $name['firstName'];
        }
        return null;
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
        $name = $this->getAttribute('name');
        if (is_array($name)) {
            return $name['lastName'];
        }
        return null;
    }

    public function getEmail(): ?string
    {
        return $this->getAttribute('email');
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
