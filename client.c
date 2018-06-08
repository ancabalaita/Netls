#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define MAX_SIZE 300000

int port;

void criptare(char mesaj[MAX_SIZE])
{
    int i,key=10;
    char ch;
    for(i=0;mesaj[i]!=0;i++)
    {
        ch=mesaj[i];
        ch=ch+key;
        mesaj[i]=ch;
    }
}

void decriptare(char mesaj[MAX_SIZE])
{
    int i,key=10;
    char ch;
    for(i=0;mesaj[i]!=0;i++)
    {
        ch=mesaj[i];
        ch=ch-key;
        mesaj[i]=ch;
    }
}

int main(int argc, char* argv[])
{
	int sd,cod_read; //sd este un socket_descriptor, 
						//adica in momentul in care se va crea socket-ul i se va asocia un int 
						//si va fi pus in tabela de descriptori a sistemului, permitand ulterior operatii de read/write
	struct sockaddr_in server;
	char director[MAX_SIZE],raspuns[MAX_SIZE];

	if(argc!=3)
    {
        printf("Argumente insuficiente");
        exit(1);
    }
    port=atoi(argv[2]);//convertesc portul din char in int

    if(-1==(sd=socket(AF_INET,SOCK_STREAM,0))) //creez un socket de tip tcp cu protocoale default (0)
    {
        perror("Eroare la crearea socketului deoarece");
        exit(2);
    }

    server.sin_family=AF_INET;
    server.sin_addr.s_addr=inet_addr(argv[1]);//convertesc adresa ip din char in IPv4 pentru server
    server.sin_port=htons(port);// convertesc portul intr-un numar short (host to network short)

    if(-1==connect(sd,(struct sockaddr *)&server,sizeof(struct sockaddr)))//incerc conectarea la server
    {
        perror("Eroare la conect deoarece");
        exit(3);
    }

    while(1)
    {
    	bzero(director,MAX_SIZE);
    	printf("Introduceti un director sau quit pentru deconectare: \n");
    	cod_read=read(0,director,MAX_SIZE);//in cod_read retin cate caractere au fost citite de la tastatura
    	if(cod_read<=0)
    	{
    		perror("Eroare la read deoarece");
    		exit(4);
    	}
    	director[cod_read]=0; //am grija sa nu am caractere straine la sfarsitul vectorului

    	criptare(director);
    	if(write(sd,director,MAX_SIZE)<=0) //trimit directorul la server
    	{
        	perror("Eroare la write deoarece");
        	exit(5);
    	}
    	bzero(raspuns,MAX_SIZE);
    	while(strlen(raspuns)==0) //cat timp raspunsul este gol
    	{
    		if(read(sd,raspuns,MAX_SIZE)<0) //read-ul este blocant(programul ar trebui sa se blocheze aici pana citeste)
	    	{
	        	perror("Eroare la preluarea mesajului deoarece");
	        	exit(6);
	    	}
	    }
	    decriptare(raspuns);
	    if(strstr(raspuns,"Conexiune incheiata cu succes")!=0)
	    {
	    	printf("%s\n",raspuns);
	    	break;
	    }
    	printf("%s\n",raspuns);
	}
    close(sd); //inchid conexiunea cu serverul; se va scoate descriptorul din tabela de descriptori a sistemului
    			// nu se vor mai putea face operatii(read/write sau altceva) pe acest descriptor pana la o redeschidere ulterioara
	return 0;
}
