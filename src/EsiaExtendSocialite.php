<?php

namespace SMSkin\SocialiteProviders\ESIA;

use SocialiteProviders\Manager\SocialiteWasCalled;

class EsiaExtendSocialite
{
    /**
     * Register the provider.
     *
     * @param SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled): void
    {
        $socialiteWasCalled->extendSocialite('esia', SocialiteProvider::class);
    }
}
