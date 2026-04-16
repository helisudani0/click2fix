FROM node:20-slim

WORKDIR /app

COPY frontend/package.json frontend/package-lock.json* ./

# Remove lock file to ensure clean install with correct versions
RUN rm -f package-lock.json && npm install

COPY frontend .

# Restrict frontend route surface to patch-workbench + login in min builds.
ENV VITE_MIN_PATCH_UI=true

CMD ["npm", "run", "dev"]
