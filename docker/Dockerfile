FROM php:8.1-cli

USER root

RUN apt-get update && \
    apt-get install -y apt-utils curl gzip

#####################################
# Composer:
#####################################
ENV COMPOSER_ALLOW_SUPERUSER 1
ENV COMPOSER_MEMORY_LIMIT -1

RUN curl -s http://getcomposer.org/installer | php && \
    echo "export PATH=${PATH}:/var/www/vendor/bin" >> ~/.bashrc && \
    mv composer.phar /usr/local/bin/composer && \
    mkdir /var/www/.composer && chown www-data:www-data -R /var/www/.composer && \
    mkdir /var/www/.config && chown www-data:www-data -R /var/www/.config

#####################################
# PHP Zip:
#####################################
ARG INSTALL_ZIP=false

RUN if [ ${INSTALL_ZIP} = true ]; then \
    apt-get install -y libzip-dev zip unzip \
        && docker-php-ext-install zip \
;fi

###########################################################################
# Enable OpenSSL GOST Provider Support:
###########################################################################
ARG OPENSSL_ENABLE_GOST_SUPPORT=false

RUN if [ ${OPENSSL_ENABLE_GOST_SUPPORT} = true ]; then \
    apt-get install -y libengine-gost-openssl1.1 && \
    sed -i '20i openssl_conf = openssl_def' /etc/ssl/openssl.cnf && \
    echo "" >>/etc/ssl/openssl.cnf && \
    echo "[openssl_def]" >>/etc/ssl/openssl.cnf && \
    echo "engines = engine_section" >>/etc/ssl/openssl.cnf && \
    echo "" >>/etc/ssl/openssl.cnf && \
    echo "[engine_section]" >>/etc/ssl/openssl.cnf && \
    echo "gost = gost_section" >>/etc/ssl/openssl.cnf && \
    echo "" >> /etc/ssl/openssl.cnf && \
    echo "[gost_section]" >>/etc/ssl/openssl.cnf && \
    echo "engine_id = gost" >>/etc/ssl/openssl.cnf && \
    echo "dynamic_path = /usr/lib/aarch64-linux-gnu/engines-1.1/gost.so" >>/etc/ssl/openssl.cnf && \
    echo "default_algorithms = ALL" >>/etc/ssl/openssl.cnf && \
    echo "CRYPT_PARAMS = id-Gost28147-89-CryptoPro-A-ParamSet" >>/etc/ssl/openssl.cnf \
;fi

#####################################
#  Clean up APT:
#####################################
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /var/www/html
