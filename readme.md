
# RestyCrypt

PHP counterpart for OpenResty [encrypted-session-nginx-module](https://github.com/openresty/encrypted-session-nginx-module).

# Usage

See `enc.php` / `dec.php`.


# Test

```bash
docker build -t restycrypt-test .
docker run -it --rm --entrypoint=/bin/bash restycrypt-test
/tmp/test.sh
```
