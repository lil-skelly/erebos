CC = gcc
FLAGS = -Wall -Wextra -Wshadow
SRC = main.c sock.c http.c utils.c fraction.c
OUT = client

all:
	$(CC) $(SRC) -o $(OUT) $(FLAGS)

debug:
	$(CC) $(SRC) -o $(OUT) $(FLAGS) -g

clean:
	rm $(OUT)
