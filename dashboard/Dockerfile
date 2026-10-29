# Public image: the sentinel-style monitoring console is the root page (graph.jrushvj.dev), also at /honeypot/.
# The React app is the attack simulator, which runs on the laptop only (dashboard/README.md), so it is not built here.
FROM nginx:1.27-alpine
COPY dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY dashboard/public/honeypot/ /usr/share/nginx/html/
COPY dashboard/public/honeypot/ /usr/share/nginx/html/honeypot/
COPY dashboard/public/slides/ /usr/share/nginx/html/slides/
