FROM node:20

WORKDIR /app

COPY package*.json ./

RUN npm install

COPY ./app ./app

ENV INFURA_API_KEY=40eb5e67f9744047b7a7684d8bea98de

ENV SERVICE_WALLET_ACCOUNT=0x71f30b7b29846a5deb9a0913b3c240b61ae027f7

ENV FLAG=hkcert24{h0p3_y0u_pa1d_10_e7h3r_f0r_th3_fl49}

CMD ["node", "app/index.js"]
