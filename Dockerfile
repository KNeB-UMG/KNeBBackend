FROM php:8.3-fpm

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    zip \
    unzip \
    libzip-dev \
    && docker-php-ext-install zip

# Install Symfony CLI
RUN curl -sS https://get.symfony.com/cli/installer | bash && \
    mv /root/.symfony5/bin/symfony /usr/local/bin/symfony

# Clear cache
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Install PHP extensions
RUN docker-php-ext-install pdo pdo_mysql mbstring exif pcntl bcmath gd

# Get latest Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /var/www/symfony

# Copy composer files
COPY composer.json composer.lock ./

# Set up the environment
ENV APP_ENV=dev
ENV APP_DEBUG=1

# Copy existing application directory
COPY . .

# Install dependencies
RUN composer install --no-scripts --no-autoloader

# Generate autoloader
RUN composer dump-autoload --optimize

# Set permissions
RUN chown -R www-data:www-data /var/www/symfony \
    && chmod -R 777 /var/www/symfony/var

EXPOSE 8000

CMD ["symfony", "server:start", "--port=8000", "--no-tls"]
