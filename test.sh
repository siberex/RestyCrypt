PHP_ENCODED=$(php /tmp/enc.php)
printf "PHP-encoded: %s\n" "$PHP_ENCODED"
echo "Decoded with Nginx:"
curl -s http://localhost/decrypt?text="$PHP_ENCODED"

NGINX_ENCODED=$(curl -s http://localhost/encrypt)
printf "Nginx-encoded: %s\n" "$NGINX_ENCODED"
echo "Decoded with PHP:"
php /tmp/dec.php "$NGINX_ENCODED"

echo
