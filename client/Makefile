CC = gcc
FLAGS = -Wall -Wextra -Wshadow -L/usr/local/lib -lssl -lcrypto
SRC = src/main.c src/sock.c src/http.c src/utils.c src/fraction.c src/crc32.c src/log.c src/cipher.c
OUT = client

all:
	$(CC) $(SRC) -o $(OUT) $(FLAGS)

debug:
	$(CC) $(SRC) -o $(OUT) $(FLAGS) -g

clean:
	rm $(OUT)
