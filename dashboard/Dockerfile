FROM node:22-alpine AS base

FROM base AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npm run build

FROM base AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
USER nextjs
EXPOSE 3000
ENV PORT=3000
# Bind to loopback by default — the dashboard is a per-operator tool, not a
# public service. Operators who want LAN access set HOSTNAME=0.0.0.0 in
# their own deployment (password still required); remote access should use
# an SSH tunnel: `ssh -L 3000:localhost:3000 <node>`.
ENV HOSTNAME="127.0.0.1"
CMD ["node", "server.js"]
