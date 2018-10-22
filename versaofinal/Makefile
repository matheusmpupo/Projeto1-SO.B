#    Ettore Biazon Baccan        - 16000465
#    Mateus Henrique Zorzi       - 16100661
#    Matheus Martins Pupo        - 16145559
#    Rodrigo Okada Mendes        - 16056848

obj-m += crypto.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc teste.c -o teste

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
