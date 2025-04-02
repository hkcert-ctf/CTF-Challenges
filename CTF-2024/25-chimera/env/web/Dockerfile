FROM webdevops/php-apache:8.0

ENV DEBIAN_FRONTEND noninteractive
ENV WEB_DOCUMENT_ROOT "/var/www/html"

COPY html /var/www/html/

COPY config/000-default.conf /opt/docker/etc/httpd/conf.d/000-default.conf

RUN a2enmod proxy proxy_fcgi

RUN chown -R root:root /var/www && \
    find /var/www -type d -exec chmod 555 {} \; && \
    find /var/www -type f -exec chmod 444 {} \;

COPY readflag.c /
COPY --chown=root:root flag.txt /flag
RUN chmod 400 /flag
RUN gcc /readflag.c -o /readflag && rm /readflag.c
RUN chmod +s /readflag
RUN mv /readflag /proof-of-onii1111-chan-$(cat /dev/urandom | tr -dc [:alnum:] | fold -w 32 | head -n 1)    