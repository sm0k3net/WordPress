#!/bin/bash

#####################################################
#Script to confiruge Server, WebServer and WordPress#
#####################################################


#Colors settings
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color


#Welcome message
clear
echo -e "Welcome to WordPress & LEMP stack installation and configuration wizard!
First of all, we going to check all required packeges..."

#Checking packages
echo -e "${YELLOW}Checking packages...${NC}"
echo -e "List of required packeges: nano, zip, unzip, mc, htop, fail2ban, nginx & php5-fpm, mysql, php curl, phpmyadmin, wget, curl"

read -r -p "Do you want to check packeges? [y/N] " response
case $response in
    [yY][eE][sS]|[yY]) 


NANO=$(dpkg-query -W -f='${Status}' nano 2>/dev/null | grep -c "ok installed")
  if [ $(dpkg-query -W -f='${Status}' nano 2>/dev/null | grep -c "ok installed") -eq 0 ];
  then
    echo -e "${YELLOW}Installing nano${NC}"
    apt-get install nano --yes;
    elif [ $(dpkg-query -W -f='${Status}' nano 2>/dev/null | grep -c "ok installed") -eq 1 ];
    then
      echo -e "${GREEN}nano is installed!${NC}"
  fi

ZIP=$(dpkg-query -W -f='${Status}' zip 2>/dev/null | grep -c "ok installed")
  if [ $(dpkg-query -W -f='${Status}' zip 2>/dev/null | grep -c "ok installed") -eq 0 ];
  then
    echo -e "${YELLOW}Installing zip${NC}"
    apt-get install zip --yes;
    elif [ $(dpkg-query -W -f='${Status}' zip 2>/dev/null | grep -c "ok installed") -eq 1 ];
    then
      echo -e "${GREEN}zip is installed!${NC}"
  fi

MC=$(dpkg-query -W -f='${Status}' mc 2>/dev/null | grep -c "ok installed")
  if [ $(dpkg-query -W -f='${Status}' mc 2>/dev/null | grep -c "ok installed") -eq 0 ];
  then
    echo -e "${YELLOW}Installing mc${NC}"
    apt-get install mc --yes;
    elif [ $(dpkg-query -W -f='${Status}' mc 2>/dev/null | grep -c "ok installed") -eq 1 ];
    then
      echo -e "${GREEN}mc is installed!${NC}"
  fi

HTOP=$(dpkg-query -W -f='${Status}' htop 2>/dev/null | grep -c "ok installed")
  if [ $(dpkg-query -W -f='${Status}' htop 2>/dev/null | grep -c "ok installed") -eq 0 ];
  then
    echo -e "${YELLOW}Installing htop${NC}"
    apt-get install htop --yes;
    elif [ $(dpkg-query -W -f='${Status}' htop 2>/dev/null | grep -c "ok installed") -eq 1 ];
    then
      echo -e "${GREEN}htop is installed!${NC}"
  fi

FAIL2BAN=$(dpkg-query -W -f='${Status}' fail2ban 2>/dev/null | grep -c "ok installed")
  if [ $(dpkg-query -W -f='${Status}' fail2ban 2>/dev/null | grep -c "ok installed") -eq 0 ];
  then
    echo -e "${YELLOW}Installing fail2ban${NC}"
    apt-get install fail2ban --yes;
    elif [ $(dpkg-query -W -f='${Status}' fail2ban 2>/dev/null | grep -c "ok installed") -eq 1 ];
    then
      echo -e "${GREEN}fail2ban is installed!${NC}"
  fi

NGINX=$(dpkg-query -W -f='${Status}' nginx 2>/dev/null | grep -c "ok installed")
  if [ $(dpkg-query -W -f='${Status}' nginx 2>/dev/null | grep -c "ok installed") -eq 0 ];
  then
    echo -e "${YELLOW}Installing nginx${NC}"
    apt-get install nginx php5-fpm --yes;
    elif [ $(dpkg-query -W -f='${Status}' nginx 2>/dev/null | grep -c "ok installed") -eq 1 ];
    then
      echo -e "${GREEN}nginx is installed!${NC}"
  fi

MYSQL=$(dpkg-query -W -f='${Status}' mysql-server 2>/dev/null | grep -c "ok installed")
  if [ $(dpkg-query -W -f='${Status}' mysql-server 2>/dev/null | grep -c "ok installed") -eq 0 ];
  then
    echo -e "${YELLOW}Installing mysql-server${NC}"
    apt-get install mysql-server --yes;
    elif [ $(dpkg-query -W -f='${Status}' mysql-server 2>/dev/null | grep -c "ok installed") -eq 1 ];
    then
      echo -e "${GREEN}mysql-server is installed!${NC}"
  fi

PHP5CURL=$(dpkg-query -W -f='${Status}' php5-curl 2>/dev/null | grep -c "ok installed")
  if [ $(dpkg-query -W -f='${Status}' php5-curl 2>/dev/null | grep -c "ok installed") -eq 0 ];
  then
    echo -e "${YELLOW}Installing php5-curl${NC}"
    apt-get install php5-curl --yes;
    elif [ $(dpkg-query -W -f='${Status}' php5-curl 2>/dev/null | grep -c "ok installed") -eq 1 ];
    then
      echo -e "${GREEN}php5-curl is installed!${NC}"
  fi

PHPMYADMIN=$(dpkg-query -W -f='${Status}' phpmyadmin 2>/dev/null | grep -c "ok installed")
  if [ $(dpkg-query -W -f='${Status}' phpmyadmin 2>/dev/null | grep -c "ok installed") -eq 0 ];
  then
    echo -e "${YELLOW}Installing phpmyadmin${NC}"
    apt-get install phpmyadmin --yes;
    elif [ $(dpkg-query -W -f='${Status}' phpmyadmin 2>/dev/null | grep -c "ok installed") -eq 1 ];
    then
      echo -e "${GREEN}phpmyadmin is installed!${NC}"
  fi

WGET=$(dpkg-query -W -f='${Status}' wget 2>/dev/null | grep -c "ok installed")
  if [ $(dpkg-query -W -f='${Status}' wget 2>/dev/null | grep -c "ok installed") -eq 0 ];
  then
    echo -e "${YELLOW}Installing wget${NC}"
    apt-get install wget --yes;
    elif [ $(dpkg-query -W -f='${Status}' wget 2>/dev/null | grep -c "ok installed") -eq 1 ];
    then
      echo -e "${GREEN}wget is installed!${NC}"
  fi

CURL=$(dpkg-query -W -f='${Status}' curl 2>/dev/null | grep -c "ok installed")
  if [ $(dpkg-query -W -f='${Status}' curl 2>/dev/null | grep -c "ok installed") -eq 0 ];
  then
    echo -e "${YELLOW}Installing curl${NC}"
    apt-get install curl --yes;
    elif [ $(dpkg-query -W -f='${Status}' curl 2>/dev/null | grep -c "ok installed") -eq 1 ];
    then
      echo -e "${GREEN}curl is installed!${NC}"
  fi

  ;;

    *)

  echo -e "${RED}
  Packeges check is ignored! 
  Please be aware, that nginx, mysql, phpmyadmin and other software may not be installed!
  ${NC}"

  ;;
esac


#creating user
echo -e "${YELLOW}Adding separate user & creating website home folder for secure running of your website...${NC}"

  echo -e "${YELLOW}Please, enter new username: ${NC}"
  read username
  echo -e "${YELLOW}Please enter website name: ${NC}"
  read websitename
  groupadd $username
  adduser --home /var/www/$username/$websitename --ingroup $username $username
  mkdir /var/www/$username/$websitename/www
  chown -R $username:$username /var/www/$username/$websitename
  echo -e "${GREEN}User, group and home folder were succesfully created!
  Username: $username
  Group: $username
  Home folder: /var/www/$username/$websitename
  Website folder: /var/www/$username/$websitename/www${NC}"


#configuring nginx
echo -e "${YELLOW}Now we going to configure nginx for your domain name & website root folder...${NC}"

read -r -p "Do you want to configure Nginx automatically? [y/N] " response
case $response in
    [yY][eE][sS]|[yY]) 

  echo -e "Please, provide us with your domain name: "
  read domain_name
  echo -e "Please, provide us with your email: "
  read domain_email
  cat >/etc/nginx/sites-available/$domain_name.conf <<EOL
# Default server configuration
#
server {
# listen 80 default_server;
  listen 80;
# listen [::]:80 default_server;
  listen [::]:80;

# Uncomment line below if using SSL
# listen 443;
  
  client_max_body_size 200m;

# If using custom SSL cert, uncommenct lines below and update them
# ssl on;
# ssl_certificate   /path/to/file.pem;
# ssl_certificate_key /path/to/file.key;


  # SSL configuration
  #
  # listen 443 ssl default_server;
  # listen [::]:443 ssl default_server;
  #
  # Self signed certs generated by the ssl-cert package
  # Don't use them in a production server!
  #
  # include snippets/snakeoil.conf;

  root /var/www/$username/$websitename/www;
  index index.php index.html index.htm;
  # Add index.php to the list if you are using PHP
  #index index.php index.htm index.html;

  server_name $domain_name;


  location / {
    index index.php index.html index.htm;
    # First attempt to serve request as file, then
    # as directory, then fall back to displaying a 404.
#   try_files $uri \uri/ =404;
    try_files \$uri \$uri/ /index.php?\$args;
#   try_files $uri =404;
  }

  # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
  #
  location ~ \.php$ {
  # include snippets/fastcgi-php.conf;
  #
  # # With php5-cgi alone:
  # fastcgi_pass 127.0.0.1:9000;
    try_files \$uri =404;
    fastcgi_split_path_info ^(.+\.php)(/.+)$;
    fastcgi_pass unix:/var/run/php5-fpm.sock;
    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    include fastcgi_params;
  # # With php5-fpm:
  # fastcgi_pass unix:/var/run/php5-fpm.sock;
  }

  # deny access to .htaccess files, if Apache's document root
  # concurs with nginx's one
  #
  #location ~ /\.ht {
  # deny all;
  #}
}
EOL

	  ln -s /etc/nginx/sites-available/$domain_name.conf /etc/nginx/sites-enabled/
    service nginx restart
    service php5-fpm restart
    P_IP="`wget http://ipinfo.io/ip -qO -`"

    echo -e "${GREEN}Nginx config was updated!
    New config file was created: /etc/nginx/sites-available/$domain_name.conf
    Domain was set to: $domain_name
    Root folder was set to: /var/www/$username/$websitename/www
    Option Indexes was set to: -Indexes (to close directory listing)
    Your server public IP is: $P_IP (Please, set this IP into your domain name 'A' record)
    Website was activated & nginx service restarted!
    ${NC}"

        ;;
    *)

  echo -e "${RED}WARNING! Nginx was not configured properly, you can do this manually or re run our script.${NC}"

        ;;
esac

php5enmod mcrypt
service php5-fpm restart

#downloading WordPress, unpacking, adding basic pack of plugins, creating .htaccess with optimal & secure configuration
echo -e "${YELLOW}On this step we going to download latest version of WordPress with EN or RUS language, set optimal & secure configuration and add basic set of plugins...${NC}"

read -r -p "Do you want to install WordPress & automatically set optimal and secure configuration with basic set of plugins? [y/N] " response
case $response in
    [yY][eE][sS]|[yY]) 

  echo -e "${GREEN}Please, choose WordPress language you need (set RUS or ENG): "
  read wordpress_lang

  if [ "$wordpress_lang" == 'RUS' ];
    then
    wget https://ru.wordpress.org/latest-ru_RU.zip -O /tmp/$wordpress_lang.zip
  else
    wget https://wordpress.org/latest.zip -O /tmp/$wordpress_lang.zip
  fi

  echo -e "Unpacking WordPress into website home directory..."
  sleep 5
  unzip /tmp/$wordpress_lang.zip -d /var/www/$username/$websitename/www/
  mv /var/www/$username/$websitename/www/wordpress/* /var/www/$username/$websitename/www
  rm -rf /var/www/$username/$websitename/www/wordpress
  rm /tmp/$wordpress_lang.zip
  mkdir /var/www/$username/$websitename/www/wp-content/uploads
  chmod -R 777 /var/www/$username/$websitename/www/wp-content/uploads

  echo -e "Now we going to download some useful plugins:
  1. Google XML Sitemap generator
  2. Social Networks Auto Poster
  3. Add to Any
  4. Easy Watermark"
  sleep 7
  
  SITEMAP="`curl https://wordpress.org/plugins/google-sitemap-generator/ | grep https://downloads.wordpress.org/plugin/google-sitemap-generator.*.*.*.zip | awk '{print $3}' | sed -ne 's/.*\(http[^"]*.zip\).*/\1/p'`"
  wget $SITEMAP -O /tmp/sitemap.zip
  unzip /tmp/sitemap.zip -d /tmp/sitemap
  mv /tmp/sitemap/* /var/www/$username/$websitename/www/wp-content/plugins/

  wget https://downloads.wordpress.org/plugin/social-networks-auto-poster-facebook-twitter-g.zip -O /tmp/snap.zip
  unzip /tmp/snap.zip -d /tmp/snap
  mv /tmp/snap/* /var/www/$username/$websitename/www/wp-content/plugins/

  ADDTOANY="`curl https://wordpress.org/plugins/add-to-any/ | grep https://downloads.wordpress.org/plugin/add-to-any.*.*.zip | awk '{print $3}' | sed -ne 's/.*\(http[^"]*.zip\).*/\1/p'`"
  wget $ADDTOANY -O /tmp/addtoany.zip
  unzip /tmp/addtoany.zip -d /tmp/addtoany
  mv /tmp/addtoany/* /var/www/$username/$websitename/www/wp-content/plugins/

  WATERMARK="`curl https://wordpress.org/plugins/easy-watermark/ | grep https://downloads.wordpress.org/plugin/easy-watermark.*.*.*.zip | awk '{print $3}' | sed -ne 's/.*\(http[^"]*.zip\).*/\1/p'`"
  wget $WATERMARK -O /tmp/watermark.zip
  unzip /tmp/watermark.zip -d /tmp/watermark
  mv /tmp/watermark/* /var/www/$username/$websitename/www/wp-content/plugins/

  rm /tmp/sitemap.zip /tmp/snap.zip /tmp/addtoany.zip /tmp/watermark.zip
  rm -rf /tmp/sitemap/ /tmp/snap/ /tmp/addtoany/ /tmp/watermark/


  echo -e "Downloading of plugins finished! All plugins were transfered into /wp-content/plugins directory.${NC}"

        ;;
    *)

  echo -e "${RED}WordPress and plugins were not downloaded & installed. You can do this manually or re run this script.${NC}"

        ;;
esac

#creating of swap
echo -e "On next step we going to create SWAP (it should be your RAM x2)..."

read -r -p "Do you need SWAP? [y/N] " response
case $response in
    [yY][eE][sS]|[yY]) 

  RAM="`free -m | grep Mem | awk '{print $2}'`"
  swap_allowed=$(($RAM * 2))
  swap=$swap_allowed"M"
  fallocate -l $swap /var/swap.img
  chmod 600 /var/swap.img
  mkswap /var/swap.img
  swapon /var/swap.img

  echo -e "${GREEN}RAM detected: $RAM
  Swap was created: $swap${NC}"
  sleep 5

        ;;
    *)

  echo -e "${RED}You didn't create any swap for faster system working. You can do this manually or re run this script.${NC}"

        ;;
esac


#phpmyadmin default path change
echo -e "${YELLOW}Changing phpMyAdmin default path from /phpMyAdmin to /myadminphp...${NC}"

read -r -p "Do you want to change default phpMyAdmin path to /myadminphp? [y/N] " response
case $response in
    [yY][eE][sS]|[yY]) 
  
sudo ln -s /usr/share/phpmyadmin /var/www/$username/$websitename/www
mv /var/www/$username/$websitename/www/phpmyadmin /var/www/$username/$websitename/www/myadminphp

echo -e "${GREEN}Path was succesfully changed!
New phpMyAdmin path is: /myadminphp (i.e.: yourwebsite.com/myadminphp)${NC}"

        ;;
    *)

  echo -e "${RED}Path was not changed!${NC}"

        ;;
esac


#creation of robots.txt
echo -e "${YELLOW}Creation of robots.txt file...${NC}"
sleep 3
cat >/var/www/$username/$websitename/www/robots.txt <<EOL
User-agent: *
Disallow: /cgi-bin
Disallow: /wp-admin/
Disallow: /wp-includes/
Disallow: /wp-content/
Disallow: /wp-content/plugins/
Disallow: /wp-content/themes/
Disallow: /trackback
Disallow: */trackback
Disallow: */*/trackback
Disallow: */*/feed/*/
Disallow: */feed
Disallow: /*?*
Disallow: /tag
Disallow: /?author=*
EOL

echo -e "${GREEN}File robots.txt was succesfully created!
Setting correct rights on user's home directory and 755 rights on robots.txt${NC}"
sleep 3

chmod 755 /var/www/$username/$websitename/www/robots.txt

echo -e "${GREEN}Configuring fail2ban...${NC}"
sleep 3
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf-old
cat >/etc/fail2ban/jail.conf <<EOL
[DEFAULT]

ignoreip = 127.0.0.1/8
ignorecommand =
bantime  = 1200
findtime = 1200
maxretry = 3
backend = auto
usedns = warn
destemail = $domain_email
sendername = Fail2Ban
sender = fail2ban@localhost
banaction = iptables-multiport
mta = sendmail

# Default protocol
protocol = tcp
# Specify chain where jumps would need to be added in iptables-* actions
chain = INPUT
# ban & send an e-mail with whois report to the destemail.
action_mw = %(banaction)s[name=%(__name__)s, port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
              %(mta)s-whois[name=%(__name__)s, dest="%(destemail)s", protocol="%(protocol)s", chain="%(chain)s", sendername="%(sendername)s"]
action = %(action_mw)s

[ssh]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5

[ssh-ddos]
enabled  = true
port     = ssh
filter   = sshd-ddos
logpath  = /var/log/auth.log
maxretry = 5


EOL

service fail2ban restart

echo -e "${GREEN}fail2ban configuration finished!
fail2ban service was restarted, default confige backuped at /etc/fail2ban/jail.conf-old
Jails were set for: ssh bruteforce, ssh ddos${NC}"

sleep 5

#nginx optimization
echo -e "${YELLOW}Do you need to optimize Nginx for low resources server? (1 Core, 1GB memory and lower)${NC}"

read -r -p "Do you want to change default nginx configuration? [y/N] " response
case $response in
    [yY][eE][sS]|[yY]) 
  
cat >/etc/nginx/nginx.conf <<EOL
user www-data;
worker_processes 1;
worker_rlimit_nofile 833;
pid /run/nginx.pid;

events {
  worker_connections 2048;
  multi_accept on;
  use epoll;
}

http {

  ##
  # Basic Settings
  ##

  sendfile on;
  tcp_nopush on;
  tcp_nodelay on;
  keepalive_timeout 30;
  keepalive_requests 1000;
  types_hash_max_size 2048;
  reset_timedout_connection on;
  client_body_timeout 10;
  # server_tokens off;

  # server_names_hash_bucket_size 64;
  # server_name_in_redirect off;

  include /etc/nginx/mime.types;
  default_type application/octet-stream;

  ##
  # SSL Settings
  ##

  ssl_protocols TLSv1 TLSv1.1 TLSv1.2; # Dropping SSLv3, ref: POODLE
  ssl_prefer_server_ciphers on;

  ##
  # Logging Settings
  ##

  #access_log /var/log/nginx/access.log;
  access_log off;
  error_log /var/log/nginx/error.log crit;

  ##
  # Gzip Settings
  ##

  gzip on;
  gzip_disable "msie6";

  # gzip_vary on;
  # gzip_proxied any;
  # gzip_comp_level 6;
  # gzip_buffers 16 8k;
  # gzip_http_version 1.1;
  # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

  ##
  # Virtual Host Configs
  ##

  include /etc/nginx/conf.d/*.conf;
  include /etc/nginx/sites-enabled/*;
}


#mail {
# # See sample authentication script at:
# # http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
# 
# # auth_http localhost/auth.php;
# # pop3_capabilities "TOP" "USER";
# # imap_capabilities "IMAP4rev1" "UIDPLUS";
# 
# server {
#   listen     localhost:110;
#   protocol   pop3;
#   proxy      on;
# }
# 
# server {
#   listen     localhost:143;
#   protocol   imap;
#   proxy      on;
# }
#}

EOL

echo -e "${GREEN}Nginx configuration was succesfully updated!
You can check it here: /etc/nginx/nginx.conf${NC}"

        ;;
    *)

  echo -e "${RED}No changes for Nginx config were applied!${NC}"

        ;;
esac


echo -e "${GREEN}Configuration of nginx was succesfully finished!
Restarting Nginx, php5-fpm & MySQL services...${NC}"

service nginx restart
service php5-fpm restart
service mysql restart

echo -e "${GREEN}Services succesfully restarted!${NC}"
sleep 3

echo -e "${GREEN}Adding user & database for WordPress, setting wp-config.php...${NC}"
echo -e "Please, set username for database: "
read db_user
echo -e "Please, set password for database user: "
read db_pass

mysql -u root -p <<EOF
CREATE USER '$db_user'@'localhost' IDENTIFIED BY '$db_pass';
CREATE DATABASE IF NOT EXISTS $db_user;
GRANT ALL PRIVILEGES ON $db_user.* TO '$db_user'@'localhost';
ALTER DATABASE $db_user CHARACTER SET utf8 COLLATE utf8_general_ci;
EOF

cat >/var/www/$username/$websitename/www/wp-config.php <<EOL
<?php

define('DB_NAME', '$db_user');

define('DB_USER', '$db_user');

define('DB_PASSWORD', '$db_pass');

define('DB_HOST', 'localhost');

define('DB_CHARSET', 'utf8');

define('DB_COLLATE', '');

define('AUTH_KEY',         '$db_user');
define('SECURE_AUTH_KEY',  '$db_user');
define('LOGGED_IN_KEY',    '$db_user');
define('NONCE_KEY',        '$db_user');
define('AUTH_SALT',        '$db_user');
define('SECURE_AUTH_SALT', '$db_user');
define('LOGGED_IN_SALT',   '$db_user');
define('NONCE_SALT',       '$db_user');

\$table_prefix  = 'wp_';

define('WP_DEBUG', false);

if ( !defined('ABSPATH') )
	define('ABSPATH', dirname(__FILE__) . '/');

require_once(ABSPATH . 'wp-settings.php');
EOL

chown -R $username:$username /var/www/$username
echo -e "${GREEN}Database user, database and wp-config.php were succesfully created & configured!${NC}"
sleep 3
echo -e "Installation & configuration succesfully finished.
Twitter: @sm0k3net
e-mail: info@sm0k3.net
Bye!"
