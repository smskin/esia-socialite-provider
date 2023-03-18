<?php

namespace SMSkin\SocialiteProviders\ESIA\Signer;

use SMSkin\SocialiteProviders\ESIA\Signer\Exceptions\SignFailException;

interface SignerInterface
{
    /**
     * @throws SignFailException
     */
    public function sign(string $message): string;
}
