FROM node:22-slim
USER root
RUN apt update \
    && apt install -y tini chromium curl \
    && apt clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /app
COPY package.json /app/
RUN npm install
RUN chmod 555 -R /app/

COPY server.js bot.js /app/
COPY proof.sh /proof.sh
RUN chmod 555 /app/server.js /app/bot.js /proof.sh

ENV H_SITEKEY 0000000000000000
ENV H_SECRET 0000000000000000
ENV HOSTNAME localhost:3000

USER node
EXPOSE 3000

ENTRYPOINT ["/bin/tini", "--"]
CMD ["node", "server.js"]