FROM openresty/openresty:1.15.8.2-buster

# Test OpenResty encrypted-session-nginx-module alongside with it’s PHP counterpart

# Install php
RUN apt update \
    && apt -y install libmcrypt-dev php7.3-dev

# Install mcrypt
RUN yes '' | pecl install mcrypt \
    && echo 'extension=mcrypt.so' > /etc/php/7.3/mods-available/mcrypt.ini \
    && phpenmod mcrypt

ENV SESSION_KEY="SomeSecret, MustBe 32 bytes long"
ENV SESSION_IV="someIV,eq16bytes"

COPY nginx.conf RestyCrypt.php enc.php dec.php test.sh /tmp/

RUN envsubst '${SESSION_KEY},${SESSION_IV}' < /tmp/nginx.conf > /usr/local/openresty/nginx/conf/nginx.conf \
    && service openresty restart

CMD /tmp/test.sh
