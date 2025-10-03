# Usa uma imagem oficial do Node.js como base (leve e estável)
FROM node:20-alpine

# Define o diretório de trabalho dentro do container
WORKDIR /usr/src/app

# Copia os arquivos package.json e package-lock.json
# Isso permite que o Docker use o cache de camadas para as dependências
COPY package*.json ./

# Instala as dependências do projeto
RUN npm install

# Copia o restante do código da aplicação para o container
# O .gitignore impede que o .env e node_modules sejam copiados
COPY . .

# Expõe a porta que o seu Express está escutando (porta 3000)
EXPOSE 3000

# Comando para iniciar o servidor
CMD [ "node", "server.js" ]