obj-m+=ebbchar.o
 
all:
	make -C /lib/modules/4.15.0versaofinal3-25-08/build/ M=$(PWD) modules 
	$(CC) testebbchar.c -o test
clean:
	make -C /lib/modules/4.15.0versaofinal3-25-08/build/ M=$(PWD) clean 
	rm test
