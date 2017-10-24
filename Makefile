default: install

debug: res_fastcgi.so
	cp res_fastcgi.so /usr/lib/asterisk/modules/res_fastcgi.so
	/sc/asterisk stop
	gdb /usr/sbin/asterisk

install: strip
	cp res_fastcgi.so.strip /usr/lib/asterisk/modules/res_fastcgi.so
	/sc/asterisk stop
	/sc/asterisk start

res_fastcgi.so: res_fastcgi.c
	gcc -g -DAST_MODULE=\"res_fastagi\" -Wall -shared -o res_fastcgi.so -fPIC res_fastcgi.c -I/mnt/buildd/asterisk-git/include
	
strip: res_fastcgi.so
	cp res_fastcgi.so res_fastcgi.so.strip
	strip res_fastcgi.so.strip

clean:
	rm -f res_fastcgi.so res_fastcgi.so.strip

