NAME	=	otp_client

SRC		=	$(wildcard *.c)

OBJ		=	$(SRC:.c=.o)

all: $(NAME)

$(NAME):
	gcc -c $(SRC) $(CFLAG)
	gcc -o $(NAME) $(OBJ) $(CFLAG)

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY:	clean fclean all
