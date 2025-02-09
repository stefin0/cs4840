INC=/usr/local/ssl/include
LIB=/usr/local/ssl/lib/

all:
	gcc -I$(INC) -L$(LIB) -o cs4840crypto cs4840crypto.c -lcrypto -ldl 

clean:
	rm -rf cs4840crypto hello.enc hello.dec
