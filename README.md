# res_fastcgi

#### FastCGI event provider for Asterisk

A small module which provides AMI messages directly to FastCGI server, such as PHP-FPM. It can be useful to process events in a custom way


compile string:

```
gcc -g -DAST_MODULE=\"res_fastagi\" \
	-Wall -shared -o res_fastcgi.so \
	-fPIC res_fastcgi.c \
	-I/opt/src/asterisk/include\
```

Replace path to your asterisk sources
