FROM nginx:1.21.6

RUN apt update
RUN apt upgrade
RUN apt install procps -y

COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./server.conf /etc/nginx/conf.d/server.conf

CMD ["/usr/sbin/nginx", "-g", "daemon off;"]
