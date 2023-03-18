<?php

namespace SMSkin\SocialiteProviders\ESIA\Providers;

use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Support\ServiceProvider as BaseServiceProvider;
use Laravel\Socialite\Contracts\Factory as SocialiteFactory;
use SMSkin\SocialiteProviders\ESIA\SocialiteProvider;

class ServiceProvider extends BaseServiceProvider
{
    /**
     * @throws BindingResolutionException
     */
    public function boot()
    {
        $socialite = $this->app->make(SocialiteFactory::class);
        $socialite->extend(
            'esia',
            static function ($app) use ($socialite) {
                $config = $app['config']['services.esia'];
                return $socialite->buildProvider(SocialiteProvider::class, $config);
            }
        );
    }
}
