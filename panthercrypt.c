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
int mode; 
char * filename; 
char * ip; 
char * port; 


void set_addr(char * addr){
	// setting ip address and port to a global variable

	//using strtok to chomping the address to ip and port
	ip = strtok(addr,":");
	port = strtok(NULL, ":");
}

void network_send(){
	
	int sockfd; // socket handler 
	struct sockaddr_in serv_addr; 
	
	if((sockfd = socket(AF_INET, SOCK_STREAM, 0))< 0)
    {	
    	
        printf("Error : Could not create socket (Check whether you have added all libraries) \n");
        exit(-1);
    }

       
    int PORT = atoi(port);

   
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT); 
    serv_addr.sin_addr.s_addr = inet_addr(ip); 

	
	if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))<0)
	    {
	      
	        printf("\n Error in establishing connection to Server\n");
	        exit(-1);
	        
	    }

	
	   FILE *fp = fopen(filename,"rb");
	   if(fp==NULL)
	   {
	       printf("encrypted file open error");
	       exit(-1);   
	   }   
	printf("Transmitting to %s:%s\n",ip,port);
	while(1){
       
        unsigned char buff[256]={0};
         int nread = fread(buff,1,256,fp);
        
        
        if(nread > 0)
        {
            write(sockfd, buff, nread);
        }

        if (nread < 256){break;} 
    }
    printf("Successfully sent the file\n");
}

void checkargs(int argc,char *argv[]){
	
	if(argc < 3){
		printf("check usage : gatorcrypt <input file> [-d < IP-addr:port >][-l]\n");
  		exit(-1);		
	}
	if((strcmp(argv[2], "-l") != 0) && (strcmp(argv[2], "-d") != 0)){
		printf("check usage : -l or -d as second arg\n");
		
  		exit(-1);
	}
	if((strcmp(argv[2], "-d") == 0) && argc < 4){
		printf("check usage : -d should follow by ip and port\n");
		
  		exit(-1);		
	}
	if((strcmp(argv[2], "-d") == 0)){
		mode = 1;
		set_addr(argv[3]); 
		filename = (char *)malloc(strlen(argv[1])+3);
		
		strcat(filename,argv[1] );
		strcat(filename,".fiu" );
		
	}
	else if((strcmp(argv[2], "-l") == 0)){
		mode = 0; // local mode is 0
		filename = (char *)malloc(strlen(argv[1])+3);
		 // setting memory to do a strcat used 3 because of the three characters we are adding ".fiu"
		strcat(filename,argv[1] );
		strcat(filename,".fiu" );
		// printf("%s\n",filename ); // debug 
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

void save_file(char * buff,char * hmac,size_t txtLength){
	FILE * f;
	if( access( filename, F_OK ) != -1 ) {
	   	printf ("File already present\n");
	    exit(33);
		
	} 
		f = fopen(filename,"wb");
		if (f){
		
		fwrite(buff, txtLength, sizeof(char), f);
		fwrite(hmac, HMAC_SIZE +1 , sizeof(char), f);
		
		fclose(f);
	}
	else{
		printf ("Error at opening file to write\n");
		exit(-1);
	}
}

char * aes_encrypt(char * txtBuffer,char * key,size_t txtLength){
	gcry_cipher_hd_t handle;
	gcry_error_t err;
	int status_encrypt;
	char *hmac;
    char * encBuffer;
    encBuffer = (char *) malloc(txtLength); 
	
    
	err = gcry_cipher_open(&handle, ENCRYPT_ALGO, ENCRYPT_MODE, GCRY_CIPHER_SECURE);
	if(err != GPG_ERR_NO_ERROR){
		printf ("Error at open: %s\n",gcry_strerror(err));
		exit(-1);
	}

	
    err = gcry_cipher_setkey(handle, key, KEYLENGTH_SHA);
    if(err != GPG_ERR_NO_ERROR){
		printf ("Error at setting key: %s\n",gcry_strerror(err));
		exit(-1);
	}

	
    err = gcry_cipher_setiv(handle, &IV, KEYLENGTH_SHA);
    if(err != GPG_ERR_NO_ERROR){
		printf ("Error at setting IV: %s\n",gcry_strerror(err));
		exit(-1);
	}

    status_encrypt = gcry_cipher_encrypt(handle, encBuffer, txtLength, txtBuffer, txtLength);
    if(status_encrypt != 0){
		printf ("Error at encrypting:%s %s\n",gcry_strerror(status_encrypt),gcry_strerror(status_encrypt));
		exit(-1);
	}

	
	hmac = get_hmac(encBuffer,key, txtLength);

	
	save_file(encBuffer,hmac,txtLength);
	printf("Successfully encrypted the inputfile to %s\n",filename);

   	if(mode == 1){
   		
   		network_send();
   	}

    return encBuffer;

}


void main(int argc, char *argv[]){
	
	checkargs(argc,argv);

	grcrypt_init();
	
	char pass[PASSLENGTH],key[KEYLENGTH_SHA], * file_contents, * cipher;
	FILE *fp;
	size_t input_length;
	printf("Password: ");
	scanf("%s", pass);

	fp=fopen(argv[1], "rb"); 
	if (fp == NULL) {
  		printf("Can't open input file.\n");
  		exit(-1);
	}
	
	get_key(pass,key);

	fseek(fp, 0, SEEK_END);
	input_length = ftell(fp) - 1;

	
	size_t new_size;
	if(input_length % KEYLENGTH_SHA == 0){
		 new_size = input_length;
		 
	}
	else{
		if(input_length < KEYLENGTH_SHA){
			new_size = KEYLENGTH_SHA;
		}
		else{
			new_size = (input_length/KEYLENGTH_SHA)*KEYLENGTH_SHA + KEYLENGTH_SHA ;
			
		}
	}
	
	file_contents = (char *)malloc(new_size*sizeof(char));
	fseek(fp, 0, SEEK_SET);
	fread(file_contents, sizeof(char), new_size, fp);
	cipher = aes_encrypt(file_contents,key,new_size);


}
