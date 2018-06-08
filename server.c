#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <arpa/inet.h>
#include <dirent.h> 
#include <pwd.h>
#include <time.h>

#define PORT 3050
#define MAX_SIZE 300000

void criptare(char mesaj[MAX_SIZE])
{
    int i,key=10;
    char ch;
    for(i=0;mesaj[i]!=0;i++)
    {
        ch=mesaj[i];//daca am 'a' il deplasez cu 10 pozitii
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

void procesare_intrare(char cale[MAX_SIZE],char raspuns[MAX_SIZE],long long *marime_director) 
{
  struct stat st;	//strctura cu informatiile despre fisierul actual
  struct passwd * pwd;//structura care imi arata permisiunile fisierului
  char perm[10] = "---------";//vectorul pentru permisiuni
  int cod, err = 0;
  char sir_final[MAX_SIZE], sir_aux[100];//sirul final va fi concatenat la sfarsitul functiei la "raspuns"

  bzero(sir_final,MAX_SIZE);
  bzero(sir_aux,100);

  strcat(sir_final,"Fisierul/folder-ul: ");
  strcat(sir_final,cale);
  strcat(sir_final,"\n");
  if (stat(cale, &st) != 0) 
  {
    printf("Eroare la stat pentru %s .\t", cale);//%s-->string
    perror("Cauza este");
    strcpy(raspuns,"Eroare la stat!");
    return;
  }

  strcat(sir_final, "\tTipul fisierului: ");
  switch (st.st_mode &S_IFMT) 
  {
  case S_IFSOCK:
    strcat(sir_final, "Socket\n");
    break;
  case S_IFLNK:
    strcat(sir_final, "Link\n");
    break;
  case S_IFREG:
    strcat(sir_final, "Fisier obisnuit\n");
    break;
  case S_IFBLK:
    strcat(sir_final, "Block device\n");
    break;
  case S_IFCHR:
    strcat(sir_final, "Character device\n");
    break;
  case S_IFIFO:
    strcat(sir_final, "FIFO\n");
    break;
  case S_IFDIR:
    strcat(sir_final, "Director\n");
    break;
  default:
    strcat(sir_final, "Unknown file type\n");
  }

  *marime_director+=(long long)st.st_size;
  sprintf(sir_aux,"\tDimensiunea: %lld octeti\n", (long long)st.st_size);//lld -->long long double
  strcat(sir_final, sir_aux);
  //in linux permisiunile sunt afisate in ordinea:user, group,altii
  //iar apoi pentru fiecare categorie in ordinea, read(r),write(w),execute(x)
  if (S_IRUSR & st.st_mode) perm[0] = 'r';
  if (S_IWUSR & st.st_mode) perm[1] = 'w';
  if (S_IXUSR & st.st_mode) perm[2] = 'x';
  if (S_IRGRP & st.st_mode) perm[3] = 'r';
  if (S_IWGRP & st.st_mode) perm[4] = 'w';
  if (S_IXGRP & st.st_mode) perm[5] = 'x';
  if (S_IROTH & st.st_mode) perm[6] = 'r';
  if (S_IWOTH & st.st_mode) perm[7] = 'w';
  if (S_IXOTH & st.st_mode) perm[8] = 'x';

  char s1[64], s2[64], s3[64];
  struct tm t1, t2, t3;
  time_t status_time = st.st_ctime, modify_time = st.st_mtime, access_time = st.st_atime;

  localtime_r( & status_time, & t1);//convertesc timpul din formatul din structura st, intr-un format de timp efectiv(data, ora)
  localtime_r( & modify_time, & t2);
  localtime_r( & access_time, & t3);

  strftime(s1, sizeof(s1), "%c", & t1);//uneste toate campurile din structura de timp intr-un singur string
  strftime(s2, sizeof(s2), "%c", & t2);//stringul va fi pus in s1,s2,s3
  strftime(s3, sizeof(s3), "%c", & t3);//%c ii semnaleaza functiei sa trateze campurile ca fiind caractere

  strcat(sir_final, "\tData ultimei schimbari de status: ");
  strcat(sir_final, s1);
  strcat(sir_final, "\n");
  strcat(sir_final, "\tData ultimei modificari: ");
  strcat(sir_final, s2);
  strcat(sir_final, "\n");
  strcat(sir_final, "\tData ultimei accesari: ");
  strcat(sir_final, s3);
  strcat(sir_final, "\n");

  strcat(sir_final, "\tPermisiunile: ");
  strcat(sir_final, perm);
  strcat(sir_final, "\n");
  if ((pwd = getpwuid(st.st_uid)) != NULL) //in pwd va fi owner-ul fisierului si id-ul acestuia
  {
    strcat(sir_final, "\tProprietarul: ");
    strcat(sir_final, pwd -> pw_name);
    strcat(sir_final, " cu UID-ul: ");
    sprintf(sir_aux, "%ld", (long)st.st_uid);//%ld-->long double
    //sprintf il folosesc de fiecare data pentru a converti un numar in format char
    strcat(sir_final, sir_aux);
    strcat(sir_final, "\n");
  } 
  else //daca proprietarul nu are un nume efectiv sau este ascuns afisez doar id-ul acestuia
  {
    sprintf(sir_aux, "\tProprietarul are UID-ul: %ld\n", (long)st.st_uid);
    strcat(sir_final, sir_aux);
  }
  strcat(sir_final, "\n");
  //am terminat de construit sirul cu toate informatiile despre fisier
  //si il pun in "raspuns", sir care va fi trimis catre client la sfarsit
  strcat(raspuns,sir_final);
}

void parcurgere_director(char cale[MAX_SIZE], char raspuns[MAX_SIZE],char director[MAX_SIZE],long long *marime_director)
{
	struct stat st;
	struct dirent * rdir;
	DIR* dir;
	char nume[MAX_SIZE];
	bzero(nume,MAX_SIZE);
	//aplic stat pe cale la momentul curent pentru a vedea tipul efectiv al fisierului(folder sau altceva)
	if (0 != stat(cale, & st))
	{
		printf("Eroare la aplicarea stat pentru: %s", cale);
		perror("Cauza: ");
		return;
	}
	if (S_ISDIR(st.st_mode))//daca este folder
	{
		if ((dir = opendir(cale)) == NULL)//deschid directorul
		{
		  printf("Eroare la deschiderea folder-ului %s", cale);
		  perror("Cauza: ");
		  return;
		}
	    while (NULL != (rdir = readdir(dir))) //parcurg fisierele din director, cat timp mai exista
	    {
	    	if (strcmp(rdir -> d_name, ".") && strcmp(rdir -> d_name, ".."))//cat timp nu este un fisier ascuns, pentru ca aceste fisiere nu au drepturi de acces sau recursivitatea ar putea continua la infinit, fiind fisiere de sistem si in plus folderul cautat de user nu este ascuns
      		{
      			char temp[MAX_SIZE];
      			bzero(temp,MAX_SIZE);
      			if(director[0]!='/')
					strcat(temp,"/");
				strcat(temp,director);
				strcat(temp,"/");
      			sprintf(nume, "%s/%s", cale, rdir -> d_name);
      			if(strstr(nume,temp)!=0)
      				procesare_intrare(nume,raspuns,marime_director);
      			parcurgere_director(nume,raspuns,director,marime_director);
      		}
	    }
	    closedir(dir);//fac close atunci cand toate fisierele din director au fost parcurse
	    			//pentru ca am terminat de verificat directorul si, facand close, il scot din tabela de descriptori
	}
}

int main(int argc, char* argv[])
{
	struct sockaddr_in server;
    struct sockaddr_in from;
    char director[MAX_SIZE], raspuns[MAX_SIZE],marime[MAX_SIZE];
    int sd,pid;
    long long marime_director;

    if(-1==(sd=socket(AF_INET, SOCK_STREAM,0)))
    {
        perror("Eroare la crearea socketul-ui deoarece");
        exit(1);
    }

    //setez optiunea de reutlizare a socketului
    //cand executia serverului este oprita exista un timp de asteptare setat pe portul aferent conexiunii
    //pana cand poate fi redeschis serverul pe acelasi port
    //prin setarea acestei optiuni, timpul de astepare va fi 0
    int opt = 1;
	if(-1==setsockopt (sd, SOL_SOCKET, SO_REUSEADDR, (void *) &opt, sizeof (opt)))
	{
		perror("Eroare la optiune socket deoarece:");
		exit(6);
	}

    bzero(&server,sizeof(server));
    bzero(&from,sizeof(from));

    server.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1",&server.sin_addr);
    server.sin_port = htons(PORT);

    if(-1==bind(sd, (struct sockaddr *) &server,sizeof(struct sockaddr)))
    {
        perror("Eroare la bind deoarece");
        exit(2);
    }

    if(-1==listen(sd,5)) //permite conectarea a maxim 5 clienti
    {
        perror("Eroare la listen");
        exit(3);
    }
    printf("Asteptam la portul %d \n",PORT);
    while(1)
    {
        int client;
        int length = sizeof(from);

        if(-1==(client = accept(sd, (struct sockaddr *) &from, &length)))//s-a conectat un client si setez canalul de comunicatie cu acesta
        {
            perror("Eroare la accept deoarece");
            exit(3);
        }
        if(-1==(pid=fork()))//fac fork pentru a asocia fiecarui client un proces diferit, independent de celelalte
        {
        	perror("Eroare la fork deoarece");
        	exit(4);
        }
        if(pid==0)//procesul copil
        {

        	printf("S-a realizat o conexiune cu un client...\n");
        	while(1)
        	{
        		bzero(director,MAX_SIZE);
        		while(strlen(director)==0)
        		{
        			if(read(client,director,MAX_SIZE)<0)
	        		{
	            		perror("Eroare la citire de la client deoarece");
	            		break;
	        		}
	        	}
        		director[strlen(director)-1]=0;

        		decriptare(director);
        		bzero(raspuns,MAX_SIZE);
        		if(strcmp(director,"quit")==0)
        		{
        			strcpy(raspuns,"Conexiune incheiata cu succes!\n");
        			criptare(raspuns);
	        		if(write(client,raspuns,MAX_SIZE)<0)
	        		{
	        			perror("Eroare la scrierea inapoi catre client deoarece");
	        			break;
	        		}
	        		break;
        		}
        		bzero(marime,MAX_SIZE);
        		marime_director=0;
        		parcurgere_director("/home",raspuns,director,&marime_director);
        		if(marime_director!=0)
        		{
        			sprintf(marime,"Spatiu total ocupat de director este de %lld octeti.\n",marime_director);
        			strcat(raspuns,marime);
        		}
        		else
        			strcat(raspuns,"Director inexistent!\n");
        		criptare(raspuns);
        		if(write(client,raspuns,MAX_SIZE)<0)
        		{
        			perror("Eroare la scrierea inapoi catre client deoarece");
        			break;
        		}
    		}
    		printf("Un client s-a deconectat. \n");
    		close(client);
    	}
    	else
    	{
    		close(client);
            while(waitpid(-1,NULL,WNOHANG));
            continue;
    	}
    }
	return 0;
}