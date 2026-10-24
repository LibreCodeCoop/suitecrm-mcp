# SPDX-FileCopyrightText: 2026 LibreCode coop and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
FROM composer:2.10.3@sha256:b6dcd72ca98fa19d0e5b8476de179859704891fad06dd9e0b96833d4c430a5fc AS vendor
WORKDIR /app
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-interaction --no-progress --prefer-dist --optimize-autoloader

FROM php:8.5.12-fpm-alpine3.24@sha256:f09d9172dd28b8696aef729ca2c2081a132c1f8d581218c99497d552c82a92df
RUN apk add --no-cache libstdc++ libsodium libcurl oniguruma \
  && apk add --no-cache --virtual .build-deps libsodium-dev curl-dev sqlite-dev oniguruma-dev \
  && docker-php-ext-install -j2 pdo_sqlite sodium curl mbstring \
  && apk del .build-deps
WORKDIR /app
COPY --from=vendor /app/vendor /app/vendor
COPY composer.json composer.lock LICENSE ./
COPY src/ src/
COPY public/ public/
COPY bin/user-access.php bin/user-access.php
RUN addgroup -S app -g 10001 && adduser -S -u 10001 -G app app \
  && mkdir -p /app/var \
  && chown -R app:app /app/var \
  && printf 'display_errors=Off\nlog_errors=On\nexpose_php=Off\nmemory_limit=128M\n' > /usr/local/etc/php/conf.d/99-app.ini \
  && sed -i 's/^user = www-data/user = app/;s/^group = www-data/group = app/' /usr/local/etc/php-fpm.d/www.conf
USER app
EXPOSE 9000
CMD ["php-fpm", "-F"]
