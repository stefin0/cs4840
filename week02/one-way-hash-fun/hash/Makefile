INC=/usr/local/ssl/include
LIB=/usr/local/ssl/lib/

all:
	gcc -I$(INC) -L$(LIB) -o cs4840hash cs4840hash.c -lcrypto -ldl 

clean:
	rm -rf cs4840hash 
