<?php

namespace SMSkin\SocialiteProviders\ESIA\Signer;

use Psr\Log\LoggerAwareTrait;
use Psr\Log\NullLogger;
use SMSkin\SocialiteProviders\ESIA\Signer\Exceptions\CannotReadCertificateException;
use SMSkin\SocialiteProviders\ESIA\Signer\Exceptions\CannotReadPrivateKeyException;
use SMSkin\SocialiteProviders\ESIA\Signer\Exceptions\NoSuchCertificateFileException;
use SMSkin\SocialiteProviders\ESIA\Signer\Exceptions\NoSuchKeyFileException;
use SMSkin\SocialiteProviders\ESIA\Signer\Exceptions\NoSuchTmpDirException;
use SMSkin\SocialiteProviders\ESIA\Signer\Exceptions\SignFailException;

abstract class AbstractSignerPKCS7
{
    use LoggerAwareTrait;

    /**
     * SignerPKCS7 constructor.
     */
    public function __construct(protected string $certPath, protected string $privateKeyPath, protected string|null $privateKeyPassword, protected string $tmpPath)
    {
        $this->logger = new NullLogger();
    }

    /**
     * @throws SignFailException
     */
    protected function checkFilesExists(): void
    {
        if (!file_exists($this->certPath)) {
            throw new NoSuchCertificateFileException('Certificate does not exist');
        }
        if (!is_readable($this->certPath)) {
            throw new CannotReadCertificateException('Cannot read the certificate');
        }
        if (!file_exists($this->privateKeyPath)) {
            throw new NoSuchKeyFileException('Private key does not exist');
        }
        if (!is_readable($this->privateKeyPath)) {
            throw new CannotReadPrivateKeyException('Cannot read the private key');
        }
        if (!file_exists($this->tmpPath)) {
            throw new NoSuchTmpDirException('Temporary folder is not found');
        }
        if (!is_writable($this->tmpPath)) {
            throw new NoSuchTmpDirException('Temporary folder is not writable');
        }
    }

    /**
     * Generate random unique string
     */
    protected function getRandomString(): string
    {
        return md5(uniqid(mt_rand(), true));
    }

    /**
     * Url safe for base64
     */
    protected function urlSafe(string $string): string
    {
        return rtrim(strtr(trim($string), '+/', '-_'), '=');
    }
}
