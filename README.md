# res_fastcgi

#### FastCGI event provider for Asterisk

A small module which provides AMI messages directly to FastCGI server, such as PHP-FPM. It can be useful to process events in a custom way

## Comparbility

Tested on Asterisk 13.13 and 16.4

## Compilation

Usual boring sequence:

`./configure && make && make install`


## Sample configuration with PHP-FPM

Make sure your listening socket is writeable by Asterisk's running user. The good idea is to create a separate pool of PHP-FPM processes by creating a file (e.g. `ast.conf`) in you fpm pool config directory (e.g. `/etc/php/7.0/fpm/pool.d/`)
```ini
[ast]
user = nobody
group = nogroup
listen = /var/run/asterisk/php-fpm.sock
listen.owner = asterisk
listen.group = asterisk
pm = static
pm.max_children = 2
```

Then restart a service - `systemctl restart php-fpm`

Now configure module definitions in `/etc/asterisk/res_fastcgi.conf`
```ini
[global]
socket = /var/run/asterisk/php-fpm.sock
script = /var/lib/asterisk/manager.php
```

Options are:
- **socket** - UNIX domain socket path of FastCGI server, default is `/var/run/asterisk/php-fpm.sock`
- **script** - Script name for FastCGI processor, default is `/var/lib/asterisk/manager.php`


Now we add some buisness-logic to a processing script (make sure it is readable by pool running user!)
```php
<?php

if ( ! in_array( $_SERVER['Event'], [ 'ChallengeSent', 'SuccessfulAuth', 'RTCPSent', 'RTCPReceived' ] ) ) {
	file_put_contents( '/tmp/debug.out', print_r( $_SERVER, 1 ), FILE_APPEND );
}
```

And finally load module via asterisk console - `asterisk -x "module load res_fastcgi"`

Now we can see file `/tmp/debug.out` populating by AMI events


