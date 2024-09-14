CC = gcc
FLAGS = -Wall -Wextra -Wshadow
SRC = src/main.c src/sock.c src/http.c src/utils.c src/fraction.c
OUT = client

all:
	$(CC) $(SRC) -o $(OUT) $(FLAGS)

debug:
	$(CC) $(SRC) -o $(OUT) $(FLAGS) -g

clean:
	rm $(OUT)
