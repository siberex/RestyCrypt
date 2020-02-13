PHP_ENCODED=$(php enc.php)
printf "PHP-encoded: %s\n" "$PHP_ENCODED"
echo "Decoded with Nginx:"
curl http://localhost/decrypt?text="$PHP_ENCODED"

NGINX_ENCODED=$(curl http://localhost/encrypt)
printf "Nginx-encoded: %s\n" "$NGINX_ENCODED"
echo "Decoded with PHP:"
php dec.php "$NGINX_ENCODED"
