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

ENV H_SITEKEY 3eb47313-f0b9-4359-9c39-d03ea1a1513a
ENV H_SECRET ES_ed7915007a594e3fb1a5903846b727aa
ENV HOSTNAME test.frames.top:8863

USER node
EXPOSE 3000

ENTRYPOINT ["/bin/tini", "--"]
CMD ["node", "server.js"]