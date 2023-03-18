<?php

namespace SMSkin\SocialiteProviders\ESIA;

use Exception;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\RequestOptions;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\User;
use SMSkin\SocialiteProviders\ESIA\Signer\Exceptions\SignFailException;
use SMSkin\SocialiteProviders\ESIA\Signer\SignerPKCS7;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;

class SocialiteProvider extends AbstractProvider
{
    /**
     * Indicates if the session state should be utilized.
     *
     * @var bool
     */
    protected $stateless = false;

    /**
     * The scopes being requested.
     *
     * @var array
     */
    protected $scopes = ['fullname', 'email'];

    protected $scopeSeparator = ' ';

    protected SignerPKCS7 $signer;

    public function __construct(Request $request, $clientId, $clientSecret, $redirectUrl, $guzzle = [])
    {
        parent::__construct($request, $clientId, $clientSecret, $redirectUrl, $guzzle);
        $this->signer = $this->getSigner();
    }

    protected function getAuthUrl($state): string
    {
        /** @noinspection PhpUndefinedFunctionInspection */
        return $this->buildAuthUrlFromBase(config('services.esia.portal_url') . '/aas/oauth2/ac', $state);
    }

    /**
     * @throws SignFailException
     * @throws Exception
     */
    protected function getCodeFields($state = null): array
    {
        $state = $state ?? $this->getState();
        $timestamp = $this->getTimeStamp();
        $message = $this->formatScopes($this->getScopes(), $this->scopeSeparator)
            . $timestamp
            . $this->clientId
            . $state;

        $fields = [
            'client_id' => $this->clientId,
            'client_secret' => $this->signer->sign($message),
            'redirect_uri' => $this->redirectUrl,
            'scope' => $this->formatScopes($this->getScopes(), $this->scopeSeparator),
            'response_type' => 'code',
            'access_type' => 'offline',
            'timestamp' => $timestamp,
            'state' => $state
        ];
        return array_merge($fields, $this->parameters);
    }

    /**
     * @throws GuzzleException
     * @throws SignFailException
     */
    public function user(): User
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $response = $this->getAccessTokenResponse($this->getCode());
        $accessToken = $this->parseAccessToken($response);

        # get object id from token
        $chunks = explode('.', $accessToken);
        $payload = json_decode($this->base64UrlSafeDecode($chunks[1]), true);

        $oid = $this->getOidFromPayload($payload);
        $this->user = $this->mapUserInfoToObject(
            $oid,
            $this->getUserInfoByToken($oid, $accessToken)
        );

        return $this->user->setToken($accessToken)
            ->setRefreshToken($this->parseRefreshToken($response))
            ->setExpiresIn($this->parseExpiresIn($response))
            ->setApprovedScopes($this->getApprovedScopes($payload['scope']));
    }

    protected function getTokenUrl(): string
    {
        /** @noinspection PhpUndefinedFunctionInspection */
        return config('services.esia.portal_url') . '/aas/oauth2/te';
    }

    /**
     * @throws GuzzleException
     * @throws SignFailException
     */
    public function getAccessTokenResponse($code)
    {
        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::HEADERS => $this->getTokenHeaders($code),
            RequestOptions::FORM_PARAMS => $this->getTokenFields($code),
            'curl' => [
                CURLOPT_SSL_VERIFYPEER => false
            ],
        ]);

        return json_decode($response->getBody(), true);
    }

    /**
     * @throws SignFailException
     * @throws Exception
     */
    protected function getTokenFields($code): array
    {
        $timestamp = $this->getTimeStamp();
        $state = $this->getState();

        $clientSecret = $this->signer->sign(
            $this->formatScopes($this->getScopes(), $this->scopeSeparator)
            . $timestamp
            . $this->clientId
            . $state
        );

        return [
            'client_id' => $this->clientId,
            'code' => $code,
            'grant_type' => 'authorization_code',
            'client_secret' => $clientSecret,
            'state' => $state,
            'redirect_uri' => $this->redirectUrl,
            'scope' => $this->formatScopes($this->getScopes(), $this->scopeSeparator),
            'timestamp' => $timestamp,
            'token_type' => 'Bearer',
            'refresh_token' => $state,
        ];
    }

    /**
     * @throws GuzzleException
     */
    private function getUserInfoByToken(string $oid, string $token): array
    {
        /** @noinspection PhpUndefinedFunctionInspection */
        $response = $this->getHttpClient()->get(config('services.esia.portal_url') . '/rs/prns/' . $oid, [
            RequestOptions::HEADERS => [
                'Authorization' => 'Bearer ' . $token
            ],
            'curl' => [
                CURLOPT_SSL_VERIFYPEER => false
            ],
        ]);
        return json_decode($response->getBody(), true);
    }

    /**
     * @throws Exception
     */
    protected function getUserByToken($token): array
    {
        throw new Exception('Unsupported method. Use getUserInfoByToken');
    }

    private function mapUserInfoToObject(string $oid, array $user): User
    {
        return (new User)->setRaw($user)->map([
            'id' => $oid,
            'nickname' => $oid,
            'name' => trim(implode(' ', [$user['lastName'] ?? null, $user['firstName'] ?? null, $user['middleName'] ?? null])),
            'email' => Arr::get($user, 'email')
        ]);
    }

    /**
     * @throws Exception
     */
    protected function mapUserToObject(array $user): User
    {
        throw new Exception('Unsupported method. Use mapUserInfoToObject');
    }

    /**
     * @throws Exception
     */
    protected function getState(): string
    {
        return sprintf(
            '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
            random_int(0, 0xffff),
            random_int(0, 0xffff),
            random_int(0, 0xffff),
            random_int(0, 0x0fff) | 0x4000,
            random_int(0, 0x3fff) | 0x8000,
            random_int(0, 0xffff),
            random_int(0, 0xffff),
            random_int(0, 0xffff)
        );
    }

    private function getSigner(): SignerPKCS7
    {
        /** @noinspection PhpUndefinedFunctionInspection */
        return new SignerPKCS7(
            $this->getPublicKeyPath(),
            $this->getPrivateKeyPath(),
            config('services.esia.private_key_password'),
            sys_get_temp_dir()
        );
    }

    private function base64UrlSafeDecode(string $string): string
    {
        $base64 = strtr($string, '-_', '+/');

        return base64_decode($base64);
    }

    private function getApprovedScopes(string $scope): array
    {
        $data = [];
        $scopes = explode($this->scopeSeparator, $scope);
        foreach ($scopes as $scope) {
            $parts = explode('?', $scope);
            $data[] = $parts[0];
        }
        return $data;
    }

    private function getOidFromPayload(array $payload): string
    {
        return $payload['urn:esia:sbj_id'];
    }

    private function getTimeStamp(): string
    {
        return date('Y.m.d H:i:s O');
    }

    /** @noinspection PhpUndefinedFunctionInspection */
    private function getPublicKeyPath(): string
    {
        $publicKey = config('services.esia.public_key');
        if (filled($publicKey)) {
            $path = tempnam(sys_get_temp_dir(), 'esiapk');
            file_put_contents($path, $publicKey);
            return $path;
        }
        return config('services.esia.public_key_path');
    }

    /** @noinspection PhpUndefinedFunctionInspection */
    private function getPrivateKeyPath(): string
    {
        $privateKey = config('services.esia.private_key');
        if (filled($privateKey)) {
            $path = tempnam(sys_get_temp_dir(), 'esiaprk');
            file_put_contents($path, $privateKey);
            return $path;
        }
        return config('services.esia.private_key_path');
    }
}
