# WordPress
LAMP &amp; LEMP installation scripts and some other stuff for WordPress

Introducing you scripts for automated LAMP & LEMP stacks installation with WordPress and HTTPS.

* wp_lamp.sh - script to install Linux, Apache, MySQL, PHP and WordPress.
* wp_lamp_https.sh - script to install LAMP stack with WordPress + configures HTTPS for your website.
* wp_lemp.sh - script to install Linux, Nginx, MySQL, php-fpm and WordPress.


All scripts helping to install & configure dependencies, software, website. They providing opmtimized configurations, adding swap for your linux system depending of your actual RAM memory. During installation process you need only to answer simple questions like "Yes", "No", and enter username & password where it is required. Except stack installation and configuration, it will help you with latest WordPress version install and config. 

You can choose English or Russian langauge of WordPress installation, also additionaly it will install you 4 very useful plugins:
 - Google XML Sitemap Generator
 - AddToAny share buttons
 - Easy Watermark
 - SNAP (Social Networks Auto Poster)
 
All config files will be generated and applied automatically, including robots.txt, .htaccess if required, nginx & apache configs, SSL config.

As of security - it will install and configure fail2ban to secure your SSH daemon from bruteforce attacks and some simple DoS attacks. For Apache stack also turns on module against Apache Overflows.

All you need to do, just copy any of this script on your server and launch it with your root user:
<pre>
$ wget https://raw.githubusercontent.com/sm0k3net/WordPress/master/wp_lamp.sh
$ chmod +x wp_lamp.sh
$ ./wp_lamp.sh
</pre>

All scripts were tested in DigitalOcean and on some small production projects.
If you will have any questions regarding this scripts or maybe want to improve something - just ping me on email info[at]sm0k3.net

