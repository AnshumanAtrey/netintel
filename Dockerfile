# Apify's Node.js 22 image (Node 18 reached end of life in April 2025). It runs as myuser,
# so the copied files are given to myuser for npm to write the lock file.
FROM apify/actor-node:22

# Copy package files
COPY --chown=myuser:myuser package*.json ./

# Install dependencies
RUN npm --quiet set progress=false \
 && npm install --omit=dev \
 && echo "installed:" && (npm ls --omit=dev --all || true)

# Copy source code
COPY --chown=myuser:myuser . ./

# Run the Actor
CMD ["npm", "start"]
