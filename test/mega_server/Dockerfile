FROM ubuntu:22.04
ENV GO_VERSION=1.22.1

WORKDIR /app

# Build dependencies:
RUN apt update -y
RUN apt upgrade -y
RUN apt-get update --fix-missing
RUN DEBIAN_FRONTEND=noninteractive apt install -y ruby-full python3-pip wget libssl-dev git libyaml-dev default-jre default-jdk nodejs postgresql postgresql-contrib mysql-server

# Debugging tools:
RUN apt install -y curl net-tools iproute2 dnsutils strace ltrace

# Install Ruby/Rails
RUN gem install rails bundler
# Install Python/Flask
RUN pip3 install requests flask pyopenssl

# Install Go
RUN export ARCH=$(dpkg --print-architecture) \
  && wget -q https://go.dev/dl/go${GO_VERSION}.linux-${ARCH}.tar.gz -O /tmp/go.tar.gz \
  && tar -C /usr/local -xf /tmp/go.tar.gz
ENV PATH "$PATH:/usr/local/go/bin:/root/go/bin"

ADD . /app

# Configure PostgreSQL for remote access
RUN sed -i "s/^#listen_addresses = 'localhost'/listen_addresses = '*'/" /etc/postgresql/14/main/postgresql.conf && \
    echo "host all all 0.0.0.0/0 md5" >> /etc/postgresql/14/main/pg_hba.conf

# Configure MySQL for remote access
RUN sed -i "s/^bind-address.*/bind-address = 0.0.0.0/" /etc/mysql/mysql.conf.d/mysqld.cnf

# Start MySQL and set up root user
RUN service mysql start && \
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY 'root';" && \
    mysql -e "CREATE USER 'root'@'%' IDENTIFIED BY 'root';" && \
    mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;" && \
    mysql -e "FLUSH PRIVILEGES;" && \
    mysql -e "CREATE DATABASE my_database;" && \
    mysql -u root -proot my_database < /app/mysql/init.sql

EXPOSE 3306
EXPOSE 5432

# Start PostgreSQL and run SQL commands in a single RUN
RUN service postgresql start && \
    su - postgres -c "psql -c \"ALTER USER postgres PASSWORD 'postgres';\"" && \
    su - postgres -c "psql -f /app/postgres/init.sql"

RUN echo "PS1='${debian_chroot:+($debian_chroot)}\[\033[01;35m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$'" >> ~/.bashrc

RUN cd go && GOARCH=$(dpkg --print-architecture) go build -o mock_server -buildvcs=false -gcflags "all=-N -l" .
RUN cd ror && bundle install

CMD ./run.sh
