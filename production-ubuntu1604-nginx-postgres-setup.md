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


#### configure apticron alerts / checks 
_if desired - helps knowing what's happening with updates
``` sh
sudo apt-get install -y apticron
``` 
point the EMAIL at your notification email address (or your email) - in the file:
``` sh
/etc/apticron/apticron.conf
# change the email address
EMAIL="your_warning@email.address"
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
    ssl_certificate /etc/ssl/certs/wildcard.las.ch.combined.crt;
    ssl_certificate_key /etc/ssl/private/wildcard.las.ch.key;
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

#### postgres and config backups - if needed


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

