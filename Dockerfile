# nFinance: Actual Budget 26.11.0 + login por usuário e senha
FROM actualbudget/actual-server:26.11.0
RUN rm -rf /app/chunks /app/node_modules/@actual-app/web/build
COPY srv/ /app/
COPY web/ /app/node_modules/@actual-app/web/build/
