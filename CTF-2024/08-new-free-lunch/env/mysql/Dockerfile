FROM mysql:8.0
COPY ./init.sql /data/application/init.sql
CMD ["--init-file", "/data/application/init.sql"]