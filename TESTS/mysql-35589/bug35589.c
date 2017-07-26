/*

export LD_LIBRARY_PATH=/export/home/sbester/server/5.0/mysql-enterprise-gpl-5.0.56-solaris10-i386/lib
/usr/local/bin/gcc bug35589.c -Wall -g -o bug35589 -L/export/home/sbester/server/5.0/mysql-enterprise-gpl-5.0.56-solaris10-i386/lib -I/export/home/sbester/server/5.0/mysql-enterprise-gpl-5.0.56-solaris10-i386/include   -lmysqlclient_r -lz -lpthread
./bug35589

*/

#include <unistd.h>
#include <pthread.h>

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <mysql.h>
/* #include <my_sys.h> */
#include <stdio.h>
#define TESTTIME (3600)
#define NUMTHREADS (3)
//char host[]="127.0.0.1";
char host[]="localhost";
int port=3306;
char username[]="root";
char password[]="";
char database[]="test";
pthread_t pthreads[NUMTHREADS];
unsigned long client_version=0;
unsigned long server_version=0;
unsigned long num_queries=0;
int threaddone=0;


int db_query(MYSQL *dbc,char *sql,int showresults);
char* alocmem(size_t num);

void *worker_thread(void *arg)
{
	MYSQL *dbc=NULL;
	my_bool auto_reconnect=1;
	int cancelstate=0;
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&cancelstate);

	dbc = mysql_init(NULL);
	if(NULL == dbc)
	{
		printf("mysql_init failed\n");
		dbc=NULL;
		goto threadexit;
	}
	else
	{
		mysql_options(dbc,MYSQL_OPT_RECONNECT,(char*)&auto_reconnect);
		if (!mysql_real_connect(dbc,host,username,password,database,port, NULL, CLIENT_FOUND_ROWS|CLIENT_MULTI_STATEMENTS|CLIENT_MULTI_RESULTS))
		{
			printf("mysql_real_connect failed: %s (%d)", mysql_error(dbc),mysql_errno(dbc));
			dbc=NULL;
		}
	}

	unsigned int counter=0;
	char shortquery[1024];
	memset(shortquery,0,1024);
	char *longquery;
	longquery=NULL;
	char *c;
	c=NULL;
	while(0==threaddone && NULL!=dbc)
	{

		if(lrand48()%6==0)
		{
			c=shortquery;
			c+=sprintf(c,"%s","grant select(id) on test.t1 to 'u");
			c+=sprintf(c,"%ld",-128 + lrand48()%255lu);
			c+=sprintf(c,"%s","'@'127.0.0.1'");
			db_query(dbc,shortquery,0);
        	}

		if(lrand48()%6==0)
		{
			for(counter=0;counter<3;counter++)
			{
				c=shortquery;
				c+=sprintf(c,"%s","drop user 'u");
				c+=sprintf(c,"%ld",-128 + lrand48()%255lu);
				c+=sprintf(c,"%s","'");
				db_query(dbc,shortquery,0);
			}

		}

		if(lrand48()%6==0)
		{
			for(counter=0;counter<3;counter++)
			{
				c=shortquery;
				c+=sprintf(c,"%s","show grants for 'u");
				c+=sprintf(c,"%ld",-128 + lrand48()%255lu);
				c+=sprintf(c,"%s","'");
				db_query(dbc,shortquery,0);
			}

		}

                if(lrand48()%6==0)
		{
			for(counter=0;counter<3;counter++)
			{
				c=shortquery;
				c+=sprintf(c,"%s","set password for 'u");
				c+=sprintf(c,"%ld",-128 + lrand48()%255lu);
				c+=sprintf(c,"%s","' = password('password')");
				db_query(dbc,shortquery,0);
			}

		}

		if(lrand48()%6==0)
		{
			for(counter=0;counter<3;counter++)
			{
				c=shortquery;
				c+=sprintf(c,"%s","flush privileges");
				db_query(dbc,shortquery,0);
			}

		}

        }
threadexit:
	mysql_close(dbc);
	mysql_thread_end();
	pthread_exit(0);
}


int main(int argc, const char *argv[])
{
	MYSQL *dbc=NULL;
	long i=0,err=0;

	srand48((unsigned long)1);
	time_t timestart=0,timenow=0;

	unsigned int counter=0;
	counter=0;
	char shortquery[1024]={0};
	char *longquery=NULL;
	longquery=NULL;
	char *c=NULL;
	/* my_init(); */
	if (!(dbc = mysql_init(NULL)))
	{
		printf("mysql_init\n");
		dbc=NULL;
		goto threadexit;
	}
	else
	{
		if (!mysql_real_connect(dbc,host,username,password,database,port, NULL, CLIENT_FOUND_ROWS|CLIENT_MULTI_STATEMENTS|CLIENT_MULTI_RESULTS))
		{
			printf("mysql_real_connect failed: %s (%d)", mysql_error(dbc),mysql_errno(dbc));
			dbc=NULL;
			goto threadexit;
		}
	}

	printf("running initializations..\n");
	client_version=mysql_get_client_version();
	server_version=mysql_get_server_version(dbc);
	printf("client version=%lu\n",client_version);
	printf("server version=%lu\n",server_version);
	if((client_version/10000) < (server_version/10000))
	{
		printf("incompatible client and server version!  please upgrade client library!\n");
		goto threadexit;
	}

	if (!mysql_thread_safe())
	{
		printf("non-threadsafe client detected!  please rebuild and link with libmysql_r!\n");
	}

	c=shortquery;
	c+=sprintf(c,"%s","drop table if exists t1");
	db_query(dbc,shortquery,1);

	c=shortquery;
	c+=sprintf(c,"%s","create table t1(id int)");
	db_query(dbc,shortquery,1);

	mysql_close(dbc);

	printf("about to spawn %d threads\n",NUMTHREADS);
	for (i=0;i<NUMTHREADS;i++)
	{
		err=pthread_create(&pthreads[i], NULL, worker_thread, (void *)i);
		if(err!=0)
		{
			printf("error spawning thread %lu, pthread_create returned %lu\n",(unsigned long)i,(unsigned long)err);
		}
		printf(".");
	}
	printf("\n");
	printf("completed spawning new database worker threads\n");

	printf("testcase is now running, so watch for server crash\n");

	timestart=time(NULL);
	timenow=time(NULL);
	for(i=0;(timenow-timestart) < TESTTIME;timenow=time(NULL))
	{
		usleep(1000*1000);
		printf("queries: %09lu\n",num_queries);
	}
	threaddone=1;

	printf("waiting for worker threads to finish...\n");

	for (i=0;i<NUMTHREADS;i++)
	{
		pthread_join(pthreads[i], NULL);
	}

	exit(0);
threadexit:
	exit(-1);
}


int db_query(MYSQL *dbc,char *sql,int showresults)
{
	int res=0;
	MYSQL_RES *r=NULL;
	MYSQL_ROW w;
	MYSQL_FIELD *field=NULL;
	int moreresult=0;
	unsigned int i=0;
	if(NULL == dbc) return 0;
	res = mysql_query(dbc,sql);
	if(res != 0 && showresults > 0)
	{
		printf("query failed '%s' : %d (%s)\n",sql,mysql_errno(dbc),mysql_error(dbc));
		return 0;
	}

	num_queries++;
	do
	{
		r = mysql_use_result(dbc);
		if(r)
		{
			unsigned int numfields = mysql_num_fields(r);
			//unsigned int numrows=mysql_num_rows(r);
			while(0!=(field = mysql_fetch_field(r)))
			{
					//print metadata information about each field
					if(showresults > 1)
					{
						printf("%s	",field->name);
					}
			}
			if(showresults > 1)
			{
				printf("\n------------------------------------\n");
			}

			while (0!=(w = mysql_fetch_row(r)))
			{
				for(i = 0; i < numfields; i++)
				{
					//print each field here
					if(showresults > 1)
					{
						printf("%s\t",w[i]);
					}
				}

				if(showresults > 1)
				{
						printf("\n");
				}
			}
			if(showresults > 1)
			{
				printf("\n");
			}
			mysql_free_result(r);
		}
		else //no rows returned. was it a select?
		{
			if(mysql_field_count(dbc) > 0 && showresults > 0)
			{
				printf("No results for '%s'.  (%d) - %s\n",sql,mysql_errno(dbc),mysql_error(dbc));
				return 0;
			}
			else //it could have been some insert/update/delete
			{
				//this is successful query
			}
		}
		moreresult=mysql_next_result(dbc);
		if(moreresult > 0 && showresults > 0)
		{
			printf("mysql_next_result returned %d, mysql error %s, (%d)\n",moreresult,mysql_error(dbc),mysql_errno(dbc));
			return 0;
		}
	} while (0==moreresult);
	return 1;
}

char* alocmem(size_t num)
{
	char *r=(char*)calloc(num,1);
	if(NULL == r)
	{
		printf("cannot calloc %I64u bytes of memory\n",(int)num);
		exit(1);
	}
	return r;
}

