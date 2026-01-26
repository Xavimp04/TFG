CC=gcc
CFLAGS=-I./include
SRC=src/main.c src/analyzer_sys.c src/analyzer_users.c src/persistence.c
OBJ=$(SRC:.c=.o)
BIN=bin/lforensic

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(BIN)

clean:
	rm -f bin/lforensic src/*.o