FROM node:20

WORKDIR /app

COPY package*.json .

RUN npm install

COPY ./app ./app

ENV INFURA_API_KEY=**REDACTED**

ENV SERVICE_WALLET_ACCOUNT=0x71f30b7b29846a5deb9a0913b3c240b61ae027f7

ENV FLAG=hkcert24{**REDACTED**}

CMD ["node", "app/index.js"]
