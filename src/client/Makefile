CC = gcc
FLAGS = -Wall -Wextra -Wshadow
SRC = main.c 
OUT = client

all:
	$(CC) $(SRC) -o $(OUT) $(FLAGS)

debug:
	$(CC) $(SRC) -o $(OUT) $(FLAGS) -g

clean:
	rm $(OUT)
