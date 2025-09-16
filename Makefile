CC      := cc
CFLAGS  := -Wall -Wextra -Werror -std=c11 -Iinclude
NAME    := woody_woodpacker

SRCS    := src/main.c src/packer.c src/encryption.c src/utils.c
OBJS    := $(SRCS:.c=.o) stub/decrypt_stub.o

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $(NAME)

src/%.o: src/%.c include/woody.h
	$(CC) $(CFLAGS) -c $< -o $@

stub/decrypt_stub.o: stub/decrypt_stub.S
	$(CC) -c $< -o $@

clean:
	rm -f $(OBJS)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
