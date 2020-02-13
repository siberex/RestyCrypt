service openresty start

PHP_ENCODED=$(php /tmp/enc.php)
printf "PHP-encoded: %s\n" "$PHP_ENCODED"
printf "Decoded with Nginx: "
curl -s http://localhost/decrypt?text="$PHP_ENCODED"

NGINX_ENCODED=$(curl -s http://localhost/encrypt)
printf "Nginx-encoded: %s\n" "$NGINX_ENCODED"
printf "Decoded with PHP: "
php /tmp/dec.php "$NGINX_ENCODED"

echo
