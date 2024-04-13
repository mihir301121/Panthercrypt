
#include <stdio.h>
#include <stdlib.h>
#include <gcrypt.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define GCRYPT_VERSION "1.5.0"

#define SALT "NaCl" 
#define PASSLENGTH 10
#define KEYLENGTH_SHA 16 
#define ITER 4096 
#define HMAC_SIZE 64 
#define ENCRYPT_ALGO GCRY_CIPHER_AES128
#define ENCRYPT_MODE GCRY_CIPHER_MODE_CBC 
#define FRAME_LENGTH 256  

static int IV[16] = {5844}; 
int mode; // Used to check which mode its running (local or daemon(i.e network))
char * port;


char * filename; 
char * encrypted_file = "temp.fiu"; 

void print_buf(char *buf,int length){
	// function to print the buffer (Mainly used to Debug the code)
	
	int i;
	for(i = 0; i < length; i++){
		printf("%02X ",(unsigned char) buf[i]); 
	}
	printf("\n");
}

void set_server(char * port){
	
	int listenfd;
    int connfd;

    
    int PORT = atoi(port);
    printf("%d\n", PORT );

    
    struct sockaddr_in serv_addr , client_addr;
    int addrlen = sizeof(client_addr);

    
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if(listenfd < 0)
    {
        printf("\n Error : Could not create socket \n");
        exit(-1);
    }

    
    int bytesReceived = 0;
    char recvBuff[256];
    memset(recvBuff, '0', sizeof(recvBuff));
    
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(PORT); 
	
	
	if(bind(listenfd, (struct sockaddr*)&serv_addr,sizeof(serv_addr)) == -1){
		printf("\n Error : Bind error \n");
		close(listenfd);
        exit(-1);
	}

	
    listen(listenfd, 5);

    
    FILE *f_out;
    
    f_out = fopen(encrypted_file, "w+b"); 
    if(f_out == NULL)
    {
        printf("Error opening file");
        error(-1);
        
    }

    
    printf("Waiting for connections.\n");
    while(1)
    {
    	
    	connfd = accept(listenfd, (struct sockaddr*)&client_addr, &addrlen);
	    
	    printf("Inbound File.\n");
	    while((bytesReceived = read(connfd, recvBuff, 256)) > 0)
	    {
	        fwrite(recvBuff, 1,bytesReceived,f_out);
	        if(bytesReceived < 256)
		    {
		        printf("Received successfully \n");
		        close(connfd);
		        fclose(f_out);
		        return;
		    }
	    }
	    close(connfd);
    }
}

void checkargs(int argc,char *argv[]){
	
	if(argc < 3){
		printf("check usage : gatordec <input file> [-d < port >][-l]\n");
  		exit(0);		
	}
	if((strcmp(argv[2], "-l") != 0) && (strcmp(argv[2], "-d") != 0)){
		printf("check usage : -l or -d as second arg\n");
		
  		exit(-1);
	}
	if((strcmp(argv[2], "-d") == 0) && argc < 4){
		printf("check usage : -d should follow by port\n");
		
  		exit(0);		
	}
	if((strcmp(argv[2], "-d") == 0)){
		mode = 1; // mode for network is 1, used in encrypt function to determine what to do with the output 
		
		filename = argv[1] ;
		set_server(argv[3]); 
	}
	else if((strcmp(argv[2], "-l") == 0)){
		mode = 0; // local mode is 0
		
		filename = (char *)malloc(strlen(argv[1])-3);
		strncpy(filename,argv[1],(strlen(argv[1])-3));
		 
	}
}

void grcrypt_init(){
	
	if (!gcry_check_version (GCRYPT_VERSION))
	 {
	   printf("libgcrypt version mismatch\n");
	   exit(-1);
	 }
	gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
}

char * read_file(FILE* fp){
	char * file_contents;
	long int input_file_size;
	fseek(fp, 0, SEEK_END);
	input_file_size = ftell(fp);
	rewind(fp);
	file_contents = malloc(input_file_size * (sizeof(char)));
	fread(file_contents, sizeof(char), input_file_size, fp);
	return file_contents;
}

size_t get_filesize(FILE* fp){
	long int input_file_size;
	input_file_size = ftell(fp) + 1;
	return input_file_size;
}

void print_key(char *key){
	
	int i;
	for(i = 0; i < KEYLENGTH_SHA; i++){
		printf("%02X ",(unsigned char) key[i]);
	}
	printf("\n"); 
}

void get_key(char *pass, char *key){
	int i, error;
	
	error = gcry_kdf_derive(pass, strlen(pass), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, SALT, 
						strlen(SALT), ITER, KEYLENGTH_SHA, key);
	if(error != 0 ){
		// return non zero if error
		printf("\n Failed with error : %s\n", gcry_strerror(error));
	}
	else{
		printf("Key: ");
		print_key(key);
	}
}

char * get_hmac(char * cipher, char * key, size_t length){
	
	gcry_error_t err;
	gcry_md_hd_t hm;
	err = gcry_md_open(&hm, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE | GCRY_MD_FLAG_HMAC);
	if(err != GPG_ERR_NO_ERROR){
		printf ("Error at opening handle for hmac: %s\n",gcry_strerror(err));
		exit(-1);
	}
	err = gcry_md_enable(hm,GCRY_MD_SHA512);
	err = gcry_md_setkey(hm, key,KEYLENGTH_SHA );
	if(err != GPG_ERR_NO_ERROR){
		printf ("Error at setting key: %s\n",gcry_strerror(err));
		exit(-1);
	}
	
  	gcry_md_write(hm,cipher,length);
  	gcry_md_final(hm);
  	

	char * hmac;
	hmac = gcry_md_read(hm , GCRY_MD_SHA512 );
	if(hmac == NULL ){
		printf ("hmac null ?\n");
		// exit(-1);
	}
	
	return hmac;
}

char * aes_decrypt(char *encBuffer,char * key,size_t txtLength,char *hmac){
	gcry_cipher_hd_t h;
	gcry_error_t err;
	int status_decrypt;
	char *hmac_gen;
	
	char * outBuffer = malloc(txtLength);
	

	
	err = gcry_cipher_open(&h, ENCRYPT_ALGO, ENCRYPT_MODE, GCRY_CIPHER_SECURE);
	if(err != GPG_ERR_NO_ERROR){
		printf ("Error at open: %s\n",gcry_strerror(err));
		exit(-1);
	}
  
    err = gcry_cipher_setkey(h, key, KEYLENGTH_SHA);
    if(err != GPG_ERR_NO_ERROR){
		printf ("Error at setting key: %s\n",gcry_strerror(err));
		exit(-1);
	}
	
    err = gcry_cipher_setiv(h, &IV, 16);
    if(err != GPG_ERR_NO_ERROR){
		printf ("Error at setting IV: %s\n",gcry_strerror(err));
		exit(-1);
	}	
	
    status_decrypt = gcry_cipher_decrypt(h, outBuffer, txtLength, encBuffer, txtLength);
    if(status_decrypt != 0){
		printf ("Error at decrypting:%s %s\n",gcry_strerror(status_decrypt),gcry_strerror(status_decrypt));
	}

	hmac_gen = get_hmac(encBuffer,key,txtLength);
	

	int j;
	for(j=0;j<64;j++){
		if (hmac_gen[j] != hmac[j]){
			printf ("HMAC verification failed\n");
			exit(62);
		}
	}
	printf("HMAC Verified\n");

	FILE * f;
	
	if( access( filename, F_OK ) != -1 ) {
	   	printf ("File already present\n");
	    exit(33);
		
	} 
	f = fopen(filename,"w+b");
	
	if (f){
		fwrite(outBuffer, txtLength -16, 1, f);
		int index,j;
		char * last_row = (outBuffer + txtLength -16);
		for(j=16;j>0;j--){
			// printf("%d %02X\n",j-1, last_row[j - 1]);
			if(last_row[j-1] != 0){
				index = j;//last non zero element
				// printf("Last index is %d %02X\n",index,last_row[j-1]);
				j = -1;
			}
		}
		fwrite(outBuffer+(txtLength -16),index+1, 1, f);
		
		fclose(f);
	}
	else{
		printf ("Error at opening file to write\n");
		exit(33);
		
	}
	return outBuffer;

}

void decrypt_file(char * encryp_filename, char * key){
	
	FILE *fh;
	fh=fopen(encryp_filename, "r");
		if (fh == NULL) {
	  		printf("Can't open input file.\n");
	  		exit(0);
		}
	char * file_contents, *hmac , *cipher;
	long int input_file_size;
	size_t input_length;
	
	fseek(fh, 0, SEEK_END);
	input_file_size = ftell(fh) - 1;
	
	hmac = (char * ) malloc(64 * (sizeof(char)));

	cipher = (char * ) malloc((input_file_size - 64) * (sizeof(char)));
	
	fseek (fh, -65L, SEEK_END);
	fread(hmac,sizeof(char),64,fh);
	
	
	rewind(fh);
	fseek (fh, 0, SEEK_SET);
	fread(cipher,sizeof(char),input_file_size-64,fh);
	

	
	aes_decrypt(cipher,key,input_file_size-64,hmac);
	// this function checks client vs generated HMAC  and also decrypts the file
}

void main(int argc, char *argv[]){
	// checking args and setting params
	checkargs(argc,argv);
	// init libgrcypt with secure memory
	grcrypt_init();

	char pass[PASSLENGTH],key[KEYLENGTH_SHA],*file_contents;
	FILE *fp;
	size_t input_length;

	
	printf("Password: ");
	scanf("%s", pass);

	
	
	get_key(pass,key);

	if(mode == 0){
		
		decrypt_file(argv[1],key);
		printf("successfully decrypted the %s file to %s\n",argv[1],filename);	
	}
	if(mode == 1){
			
		decrypt_file(encrypted_file,key);
		printf("successfully received and decrypted\n");
		remove(encrypted_file);	
	}
}
