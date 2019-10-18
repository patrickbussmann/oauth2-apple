<?php namespace League\OAuth2\Client\Provider;

use League\OAuth2\Client\Tool\ArrayAccessorTrait;

/**
 * @property array $response
 * @property string $uid
 */
class AppleResourceOwner extends GenericResourceOwner
{

    use ArrayAccessorTrait;

    /**
     * Raw response
     *
     * @var array
     */
    protected $response = [];

    /**
     * @var string|null
     */
    private $email;

    /**
     * Gets resource owner attribute by key. The key supports dot notation.
     *
     * @return mixed
     */
    public function getAttribute($key)
    {
        return $this->getValueByKey($this->response, (string) $key);
    }

    /**
     * Get user first name
     *
     * @return string|null
     */
    public function getFirstName()
    {
        return $this->getAttribute('name')['firstName'];
    }

    /**
     * Get user user id
     *
     * @return string|null
     */
    public function getId()
    {
        return $this->resourceOwnerId;
    }

    /**
     * Get user last name
     *
     * @return string|null
     */
    public function getLastName()
    {
        return $this->getAttribute('name')['lastName'];
    }

    /**
     * Get user email, if available
     *
     * @return string|null
     */
    public function getEmail()
    {
        return $this->getAttribute('email');
    }

    /**
     * Return all of the owner details available as an array.
     *
     * @return array
     */
    public function toArray()
    {
        return $this->response;
    }
}
