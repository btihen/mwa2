# Ubuntu 16.04 Production Setup
### _Using Nginx and PostgreSQL_

## BASIC UBUNTU SETUP

#### Install Ubuntu 16.04
I like using the netinstall or OpenStack (but what ever method you use **create enough hard drive space _(or add a separate drive for storage - not covered here)_** to hold all the software munki will serve (with about 20% extra space).

#### update the system before getting started

``` sh
#### updates before getting started
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get dist-upgrade -y
sudo apt-get autoremove -y
sudo reboot
```


#### config auto updates
helpful when on vacation - UBUNTU does a great job testing - I haven't had any problems!
_(I use the following settings)_
``` sh
sudo apt-get install -y unattended-upgrades
sudo su
cp /etc/apt/apt.conf.d/50unattended-upgrades /etc/apt/apt.conf.d/50unattended-upgrades.bak
cat <<"EOF" > /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
        "Ubuntu precise-security";
//      "Ubuntu precise-updates";
};
EOF
cp /etc/apt/apt.conf.d/10periodic /etc/apt/apt.conf.d/10periodic.bak
cat <<"EOF" > /etc/apt/apt.conf.d/10periodic
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
exit
```


#### add / configure postfix
``` sh
sudo apt-get install -y postfix heirloom-mailx
sudo postconf -e "sender_canonical_maps = hash:/etc/postfix/sender_canonical"
sudo postconf -e "recipient_canonical_maps = hash:/etc/postfix/recipient_canonical"
sudo su
touch /etc/postfix/sender_canonical
touch /etc/postfix/recipient_canonical
# setup to send from your alerty notification email address
cat <<"EOF" > /etc/postfix/sender_canonical
root     notify@your.domain.name
ubuntu   notify@your.domain.name
deploy   notify@your.domain.name
manager  notify@your.domain.name
logwatch notify@your.domain.name
EOF
# setup to SEND to your alert nofifing email address when there are problems
cat <<"EOF" > /etc/postfix/recipient_canonical

root    notify@your.alert.system
        notify@your.alert.system
deploy  notify@your.alert.system
ubuntu  notify@your.alert.system
manager notify@your.alert.system
EOF
exit
sudo postmap /etc/postfix/sender_canonical
sudo postmap /etc/postfix/recipient_canonical
sudo service postfix reload
```
test postfix sends an email as expected!



#### add / configure logwatch - _if desired_
``` sh
sudo apt-get -y install logwatch
sudo vim /usr/share/logwatch/default.conf/logwatch.conf
# find:
# MailTo = root
# change to:
# MailTo = notify@your.alert.system
```


#### configure apticron alerts / checks 
_if desired - helps knowing what's happening with updates
``` sh
sudo apt-get install -y apticron
``` 
point the EMAIL at your notification email address (or your email) - in the file:
``` sh
/etc/apticron/apticron.conf
# change the email address
EMAIL="notify@your.alert.system"
```


#### check update /etc/hosts
_only needed when using openstack_

``` sh
sudo su -
cp /etc/hosts /etc/hosts.bak
cat <<"EOF" > /etc/hosts
127.0.0.1 localhost
your.srver.ip.address servername.dns.name servername

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF
exit
```

#### install **ntp** (time syncing)
``` sh

sudo apt-get install -y ntp ntpdate
# force a time sync over time (now)
ntpdate -d ch.pool.ntp.org

```

#### setup time zone
if desired _makes reading logs easier_
``` sh
sudo dpkg-reconfigure tzdata
```

#### fix perl settings - _(system wide)_
this fixes annoying error messages when using **psql** and perl
``` sh
sudo cp /etc/environment /etc/environment.bak
sudo su -
cat <<"EOF" >> /etc/environment
LC_ALL=en_US.UTF-8
LANG=en_US.UTF-8
EOF
exit
```

#### configure postfix and email settings for alerts




reboot now to allow the above updates and settings take effect
``` sh
sudo reboot
```

## MWA2 SETUP 

#### Install postgresql & dev drivers for python
``` sh
sudo apt-get install -y libpq-dev postgresql postgresql-contrib 
sudo -u postgres createuser `whoami` -s
createdb `whoami`
```


#### install nginx _(**nginx-extras** is needed for webdab)!_
``` sh
sudo apt-get install -y nginx nginx-extras
```

#### Install **python 2**
``` sh
sudo apt-get install -y python-pip

# install easy install to install python virtual environments
sudo easy_install virtualenv
sudo pip install --upgrade pip
```

#### create the directories needed for the munki install and munki repo
``` sh
sudo mkdir -p /var/www
sudo mkdir -p /var/www/munki
sudo mkdir -p /var/www/munki/repo
sudo mkdir -p /var/www/munki/repo/catalogs
sudo mkdir -p /var/www/munki/repo/client_resources
sudo mkdir -p /var/www/munki/repo/icons
sudo mkdir -p /var/www/munki/repo/manifests
sudo mkdir -p /var/www/munki/repo/pkgs
sudo mkdir -p /var/www/munki/repo/pkgsinfo
```

#### setup the file permissions 
_we'll adjust them at the end - during install full user permissions is easiest
``` sh
sudo chown -R `whoami`.`whoami` /var/www/munki
sudo chown -R `whoami`.www-data /var/www/munki/repo
```

#### create virtual python environment
``` sh
cd /var/www/munki
virtualenv mwa2_env
```

#### start python virtual environment
``` sh
cd mwa2_env/
source bin/activate
```

#### install Django and the necessary supporting python software libraries
``` sh
pip install Django==1.9.1
pip install django-wsgiserver==0.8.0rc1
pip install psycopg2
pip install gunicorn
# optional, if you plan to setup LDAP authentication)
# pip install django-auth-ldap
```

#### change this file to work with django 1.9.x
``` sh
vim /var/www/munki/mwa2_env/lib/python2.7/site-packages/django_wsgiserver/management/commands/runwsgiserver.py
# Change line 326 from:
#         self.validate(display_num_errors=True)
# to
#         self.check(display_num_errors=True)
```

#### Clone (install) the mwa2 code from GitHub
``` sh
git clone https://github.com/munki/mwa2.git
```

#### Clone (install) the supporting munkitools
``` sh
git clone https://github.com/munki/munki.git
```

#### configure the munki settings.py
``` sh
cp mwa2/munkiwebadmin/settings_template.py mwa2/munkiwebadmin/settings.py
vim mwa2/munkiwebadmin/settings.py
# 1)
# Edit line 224 of mwa2/munkiwebadmin/settings.py, pointing MUNKI_REPO_DIR to the filesystem path to your repo
# From
# MUNKI_REPO_DIR = '/Users/Shared/munki-repo'
# to:
MUNKI_REPO_DIR = '/var/www/munki/repo'

# 2)
# Edit line 242 of mwa2/munkiwebadmin/settings.py to point MAKECATALOGS_PATH
# from:
# MAKECATALOGS_PATH = '/usr/local/munki/makecatalogs'
# to:
MAKECATALOGS_PATH = '/var/www/munki/mwa2_env/munki/code/client/makecatalogs'

# 3) point files to the main directory
# find
STATIC_URL = '/static/'
# add the below the above line
STATIC_ROOT = os.path.join(BASE_DIR, 'static/')

# 4) confgure PSQL setup
# find the following
# setup database (postgres? or sqlite3 is the default)
# sqlite3
# DATABASES = {
#     'default': {
#         'ENGINE': 'django.db.backends.sqlite3',
#         'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
#     }
# }
# replace it with the following
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'munkiwebadmin',
        'USER': 'munkiwebadmin',
        'PASSWORD': 'a_secret_db_password',
        'HOST': 'localhost',   # or use 'your.remote.psql.ip'
        'PORT': '',
    }
}
```

#### configure the psql database to work with django
``` sh
sudo -u postgres createuser munkiwebadmin
createdb munkiwebadmin
psql
ALTER USER "munkiwebadmin" WITH PASSWORD 'a_secret_db_password';
ALTER ROLE munkiwebadmin SET client_encoding TO 'utf8';
ALTER ROLE munkiwebadmin SET default_transaction_isolation TO 'read committed';
ALTER ROLE munkiwebadmin SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE munkiwebadmin TO munkiwebadmin;
\q
```

#### Initialize the app database
``` sh
python mwa2/manage.py migrate
```


#### create the munki login superuser
``` sh
python mwa2/manage.py createsuperuser
# store this in a vault so you can loginto https://the.munki.ip.address/
```

##### change the password of the superuser (username)
``` sh
# instructions from: http://dustindavis.me/how-to-reset-a-django-admin-password/
python manage.py shell
>>> from django.contrib.auth.models import User
>>> u = User.objects.get(username='manager')
>>> u.set_password('another_secret_password')
>>> u.save()
>>> exit()
```

#### setup css, etc to be seen / served by nginx
``` sh
python mwa2/manage.py collectstatic
# answer yes
```

#### start/test the python environment
``` sh
python mwa2/manage.py runwsgiserver host=0.0.0.0 port=8080
# go to http://your.munki.ip.address:8080
# hopefully it works
ctrl+c
```

#### test your gunicorn environment
``` sh
cd /var/www/munki/mwa2/
gunicorn --bind 0.0.0.0:8000 munkiwebadmin.wsgi:application
# go to http://your.munki.ip.address:8000
# hopefully it works
ctrl+c
``` 

#### now you can deactive the python environment
``` sh
deactivate
```

## CONFIGURE NGINX and GUNICORN to autostart and serve munki

#### finalize munki and munki repo permissions two work with gunicorn and nginx
``` sh
# sudo chown -R `whoami`.www-data /var/www/munki
```

#### make gunicorn a system resource
``` sh
sudo su 
cat <<EOF > /etc/systemd/system/gunicorn.service
[Unit]
Description=gunicorn daemon
After=network.target

[Service]
# BE SURE this is the user that results from who am i
User=`whoami`
Group=www-data
WorkingDirectory=/var/www/munki/mwa2_env/mwa2
ExecStart=/var/www/munki/mwa2_env/bin/gunicorn --workers 3 --bind unix:/var/www/munki/mwa2_env/mwa2/munkiwebadmin.sock munkiwebadmin.wsgi:application

[Install]
WantedBy=multi-user.target
EOF
exit
```

#### test the gunicorn setup
```
/var/www/munki/mwa2_env/bin/gunicorn --workers 3 --bind unix:/var/www/munki/mwa2_env/mwa2/munkiwebadmin.sock munkiwebadmin.wsgi:application
# make sure you get no errors and can find the file:
#   /var/www/munki/mwa2_env/mwa2/munkiwebadmin.sock
```

#### enable gunicorn to run 
``` sh
# start the gunicorn resource script from systemctl
sudo systemctl start gunicorn
# test there are no errors and you find the expected file:
#   /var/www/munki/mwa2_env/mwa2/munkiwebadmin.sock

# assuming all works then start the service now
sudo systemctl enable gunicorn

```

#### install your certs
``` sh
sudo su

##########
# ADD YOU CERT
cat <<EOF > /etc/ssl/certs/your_org_name.crt
-----BEGIN CERTIFICATE-----
cert here
-----END CERTIFICATE-----
EOF
chown root.ssl-cert /etc/ssl/certs/your_org_name.crt
chmod 640 /etc/ssl/certs/your_org_name.crt
# verify it is correct with
ls -als /etc/ssl/certs | grep your_org_name
#  4 -rw-r----- 1 root ssl-cert   1836 Nov  7 13:21 your_org_name.crt


##########
# YOU MAY NEED A COMBINED CERT INSTALLED
cat <<EOF > /etc/ssl/certs/your_org_name.combined.crt
-----BEGIN CERTIFICATE-----
cert here
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
cert here
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
cert here
-----END CERTIFICATE-----
EOF
chown root.ssl-cert /etc/ssl/certs/your_org_name.combined.crt
chmod 640 /etc/ssl/certs/your_org_name.combined.crt
# verify it is correct with
ls -als /etc/ssl/certs | grep your_org_name
# 8 -rw-r----- 1 root ssl-cert   5426 Nov  8 11:38 your_org_name.combined.crt
# 4 -rw-r----- 1 root ssl-cert   1836 Nov  8 11:38 your_org_name.crt


##########
# CERT PROVIDER CHANGE (if needed - not usually needed)
cat <<EOF > /etc/ssl/certs/cert_provider_chain.crt
-----BEGIN CERTIFICATE-----
cert here
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
cert here
-----END CERTIFICATE-----
EOF
chown root.ssl-cert /etc/ssl/certs/cert_provider_name_chain.crt
chmod 640 /etc/ssl/certs/cert_provider_chain.crt
# verify it is correct with
ls -als /etc/ssl/certs | grep cert_provider_name
#  4 -rw-r----- 1 root ssl-cert   1836 Nov  7 13:21 cert_provider_chain.crt


##########
# YOUR PRIVATE KEY
cat <<EOF > /etc/ssl/private/your_org_name.key
-----BEGIN RSA PRIVATE KEY-----
key here
-----END RSA PRIVATE KEY-----
EOF
chown root.ssl-cert /etc/ssl/private/your_org_name.key
chmod 640 /etc/ssl/private/your_org_name.key
# verify it is correct with
ls -als  /etc/ssl/private | grep your_org_name
#  4 -rw-r----- 1 root ssl-cert 1679 Nov  8 11:39 your_org_name.key
exit
```


#### nginx to use webdav and gunicorn
``` sh
# configure nginx
sudo su -

cat <<"EOF" > /etc/nginx/sites-available/munki
server {
    listen 80;
    server_name  server.dns.name;
  
    location / {
      if ($request_method = POST) {
        # use temporary to allow for POST to go through
        # 301 will only work for GET/HEAD/OPTIONS
        return 307 https://$host$request_uri;
      }
      return 301 https://$host$request_uri;
    }
    # return       301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name  server.dns.name;

  # HTML / PROXY OPTIONS
    # client_max_body_size 0;
    # proxy_read_timeout 300;  # answer from server, 5 min
    # proxy_send_timeout 300;  # chunks to server, 5 min
    # proxy_set_header  Host $host;
    # proxy_set_header  X-Real-IP $remote_addr;
    # proxy_set_header  X-Forwarded-For $proxy_add_x_forwarded_for;
    # proxy_set_header  X-Forwarded-Proto $scheme;
    # port_in_redirect  off;

    # add Strict-Transport-Security to prevent man in the middle attacks
    add_header Strict-Transport-Security "max-age=31536000";
    
    # SSL OPTIONS
    ssl on;
    # ssl_session_timeout 5m;
    ssl_certificate /etc/ssl/certs/server_name.combined.crt;
    ssl_certificate_key /etc/ssl/private/server_name.key;
    # ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    # ssl_prefer_server_ciphers on;
    # ssl_ciphers "EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EECDH EDH+aRSA RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS !RC4";

    # WEBDAV OPTIONS
    location /repo {
      root      /var/www/munki/;

      auth_basic "Not currently available";
      auth_basic_user_file /etc/nginx/.htpasswd;

      client_body_temp_path /var/www/munki/temp;

      dav_methods     PUT DELETE MKCOL COPY MOVE;
      dav_ext_methods   PROPFIND OPTIONS;

      create_full_put_path  on;
      dav_access    user:rw group:rw all:rw;
      autoindex     on;
    }

    location = /favicon.ico { access_log off; log_not_found off; }
    location /static/ {
        # root /var/www/munki/mwa2_env/mwa2;
        alias   /var/www/munki/mwa2_env/mwa2/munkiwebadmin/static/;
    }

    location / {
        include proxy_params;
        proxy_pass http://unix:/var/www/munki/mwa2_env/mwa2/munkiwebadmin.sock;
    }

    # Error pages
    error_page 500 502 503 504 /500.html;
    location = /500.html {
        root /var/www/munki/mwa2_env/mwa2/munkiwebadmin/templates/;
    }
}
EOF
exit
```

#### setup nginx configurations
``` sh
# disable the default nginx settings
sudo rm /etc/nginx/sites-enabled/default

# setup the new nginx settings
sudo ln -s /etc/nginx/sites-available/munki /etc/nginx/sites-enabled

# test the nginx config
sudo nginx -t

# restart your nginx (or reload if you wish)
sudo service nginx restart
# sudo service nginx reload
```

connect to https://your.munki.ip.address 
you should now see a nicely formatted login.


#### Configure the password for webdav using htpasswd
``` sh
sudo sh -c "echo -n 'manager:' >> /etc/nginx/.htpasswd"
sudo sh -c "openssl passwd -apr1 >> /etc/nginx/.htpasswd"
```
connect via webdav to your.munki.ip.address
ideally now you see the repo folders


## finalize production setup

#### setup monitoring -- we use MONIT
monitoring postgres and gunicorn socket and nginx port 80 and 443

# add / configure monit -- for standard monitoring and web usage
sudo apt-get install -y build-essential libssl-dev bison flex openssl monit

sudo su
touch /etc/monit/monit.pem
# combine cert and and authority certs
cat <<"EOF" >> /etc/monit/monit.pem
-----BEGIN PRIVATE KEY-----
private key here
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
cert here
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
cert here
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
cert here
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
cert here
-----END CERTIFICATE-----
EOF
/usr/bin/openssl gendh 512 >> /etc/monit/monit.pem
/usr/bin/openssl x509 -subject -dates -fingerprint -noout -in /etc/monit/monit.pem

#### configure monit settings
``` sh
sudo su
chmod 700 /etc/monit/monit.pem
touch /etc/monit/monitrc
cat <<"EOF" > /etc/monit/monitrc
## Start Monit in the background (run as a daemon):
#
set daemon 120             # check services at 2-minute intervals
  #with start delay 240     # optional: delay the first check by 4-minutes (by

# set logfile syslog facility log_daemon
set logfile /var/log/monit.log

#
# set idfile /var/.monit.id
set idfile /var/lib/monit/id

#
set statefile /var/lib/monit/state

#
set eventqueue
  basedir /var/lib/monit/events # set the base directory where events will be stored
  slots 100                     # optionally limit the queue size

# mail server
set mailserver smtp.domain.name

# send performance problems to itsupport for fixing during work hours
set alert nofify@your.alert.system but not on { nonexist, instance, action, pid, ppid, status } mail-format {
from: notify@your.domain.name
subject: checkin - $DESCRIPTION
message: $DATE - $ACTION $SERVICE
}

set httpd port 2812 and
    SSL ENABLE
    PEMFILE /etc/monit/monit.pem
    ALLOWSELFCERTIFICATION
    allow localhost
    allow 10.10.20.10
    allow 10.174.32.202
    allow 10.174.32.206
    allow 10.182.40.0/24
    allow 10.190.32.0/19
    allow admin:rhinJiY2tGxXnP6PZJEuCFWPtDRmPRy

###############################################################################
## CORE Services - updated for Ubuntu 1404
###############################################################################

check system systats
  if loadavg (1min) > 2.0 for 4 cycles then alert
  if loadavg (5min) > 1.8 for 4 times within 5 cycles then alert
  if memory usage > 90% for 2 cycles then alert
  if cpu usage (user) > 95% for 4 times within 5 cycles then alert
  if cpu usage (system) > 65% for 10 times within 15 cycles then alert
  if cpu usage (wait) > 75% for 5 cycles then alert

check device rootfs with path /
  if space usage > 85% for 10 times within 15 cycles then alert
  if space usage > 90% for 15 cycles then alert
  if space usage > 95% for 15 cycles then alert
  if space usage > 96 % then stop
  if inode usage > 80% for 10 times within 15 cycles then alert
  if inode usage > 90% for 15 cycles then alert
  if inode usage > 95% for 15 cycles then alert
  if inode usage > 96 % then stop

check device bootfs with path /boot
  if space usage > 80% for 10 times within 15 cycles then alert
  if space usage > 90% for 15 cycles then alert
  if space usage > 95% for 15 cycles then alert
  if space usage > 96 % then stop
  if inode usage > 80% for 10 times within 15 cycles then alert
  if inode usage > 90% for 15 cycles then alert
  if inode usage > 95% for 15 cycles then alert
  if inode usage > 96 % then stop

check process sshd with pidfile /var/run/sshd.pid
  restart program = "/usr/sbin/service ssh restart"
  start program = "/usr/sbin/service ssh start"
  stop  program = "/usr/sbin/service ssh stop"
  if failed port 22 protocol ssh then restart
  if 5 restarts within 5 cycles then timeout

check process cron with pidfile /var/run/crond.pid
  restart program = "/usr/sbin/service cron restart"
  start program = "/usr/sbin/service cron start"
  stop  program = "/usr/sbin/service cron stop"
  if 5 restarts within 5 cycles then timeout

check process ntpd with pidfile /var/run/ntpd.pid
  restart program = "/usr/sbin/service ntp restart"
  start program = "/usr/sbin/service ntp start"
  stop  program = "/usr/sbin/service ntp stop"
  if failed host 127.0.0.1 port 123 type udp for 2 times within 3 cycles then restart
  if failed host 127.0.0.1 port 123 type udp for 4 times within 5 cycles then alert
  if 4 restarts within 6 cycles then timeout

check process rsyslogd with pidfile /var/run/rsyslogd.pid
  restart program = "/usr/sbin/service rsyslog restart"
  start program = "/usr/sbin/service rsyslog start"
  stop program = "/usr/sbin/service rsyslog stop"
  if 5 restarts within 5 cycles then timeout

check file syslogd_file with path /var/log/syslog
  if timestamp > 65 minutes then alert # Have you seen "-- MARK --"?

check process postfix with pidfile /var/spool/postfix/pid/master.pid
  restart program = "/usr/sbin/service postfix restart"
  start program = "/usr/sbin/service postfix start"
  stop  program = "/usr/sbin/service postfix stop"
  if failed port 25 protocol smtp then restart
  if 5 restarts within 5 cycles then timeout

###################################################################################
## Includes -- for Business Services
###################################################################################
##
## It is possible to include additional configuration parts from other files or
## directories.
#
include /etc/monit/conf.d/*
EOF
chmod 0600 /etc/monit/monitrc

cat <<"EOF" > /etc/monit/conf.d/nginx.conf
check process nginx-80 with pidfile /var/run/nginx.pid
  restart program = "/usr/sbin/service nginx restart"
  start program = "/usr/sbin/service nginx start"
  stop program  = "/usr/sbin/service nginx stop"
  if failed host 127.0.0.1 port 80
     protocol http request "/"
     with timeout 15 seconds
     then restart
  if 4 restarts within 5 cycles then timeout

check host nginx-80-response with address localhost
  if failed host localhost port 80 protocol http request "/"
     with timeout 5 seconds for 3 cycles then alert
  alert nofify@your.alert.system { connection, timeout } with mail-format {
    from: notify@your.domain.name
    subject: servername - $DESCRIPTION
    message: $DATE - $ACTION $SERVICE
  }
EOF
chmod 0600 /etc/monit/conf.d/nginx.conf


########
# setup nginx 443 (ssl monitoring)
cat <<"EOF" > /etc/monit/conf.d/nginx-443.conf
check process nginx-443 with pidfile /var/run/nginx.pid
  restart program = "/usr/sbin/service nginx restart"
  start program = "/usr/sbin/service nginx start"
  stop program  = "/usr/sbin/service nginx stop"

  if failed host your.server.domain.name port 443 type TCPSSL
    # use your cert if you wish to carefully check these
    # certmd5 D9-31-5E-2C-58-AE-DF-45-D9-B3-25-47-B6-89-11-03
    protocol http request "/"
    with timeout 15 seconds for 2 cycles
    then restart
  if 4 restarts within 5 cycles then timeout

check host nginx-443-response with address server.domain.name
  if failed host your.server.domain.name port 443 type tcpssl
     protocol http request "/"
     with timeout 5 seconds for 4 cycles
     then alert
  alert nofify@your.alert.system { connection, timeout } with mail-format {
     from: notify@your.domain.name
     subject: servername - $DESCRIPTION
     message: $DATE - $ACTION $SERVICE
  }
EOF
chmod 0600 /etc/monit/conf.d/nginx-443.conf

#######
# monitor postgres


#######
# monitor gunicorn


exit
```

#### test config is good
``` sh
sudo monit -t -c /etc/monit/monitrc
```

#### restart monit with new config
``` sh
sudo service monit restart
```

#### check that all is running as expected
``` sh
sudo monit summary
```



#### configurfe backups


## resources used to build this article
``` sh
# for MUNKI setup
# take from: https://github.com/munki/mwa2/wiki/RHEL7-setup-notes
# for postgres
# https://www.digitalocean.com/community/tutorials/how-to-set-up-django-with-postgres-nginx-and-gunicorn-on-ubuntu-16-04
# http://michal.karzynski.pl/blog/2013/06/09/django-nginx-gunicorn-virtualenv-supervisor/
# https://www.digitalocean.com/community/tutorials/how-to-deploy-python-wsgi-apps-using-gunicorn-http-server-behind-nginx

# for apache
# https://www.digitalocean.com/community/tutorials/how-to-serve-django-applications-with-apache-and-mod_wsgi-on-ubuntu-16-04

# also check for help in apache config with: 
# https://www.digitalocean.com/community/tutorials/how-to-run-django-with-mod_wsgi-and-apache-with-a-virtualenv-python-environment-on-a-debian-vps

# https://www.williamjbowman.com/blog/2015/07/24/setting-up-webdav-caldav-and-carddav-servers/
# https://opensource.ncsa.illinois.edu/confluence/display/ERGO/Creating+a+WebDAV+repository+server+with+NGINX

# htpasswd setup
# https://www.digitalocean.com/community/tutorials/how-to-set-up-password-authentication-with-nginx-on-ubuntu-14-04
```

