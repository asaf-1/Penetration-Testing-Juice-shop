FROM mcr.microsoft.com/playwright:v1.60.0-noble

WORKDIR /work

COPY package*.json ./
RUN npm ci

COPY . .
RUN mkdir -p /work/reports /work/test-results /work/playwright-report && chown -R pwuser:pwuser /work

ENV CI=true
ENV REPORTS_DIR=/work/reports

USER pwuser

CMD ["npm", "run", "audit"]
