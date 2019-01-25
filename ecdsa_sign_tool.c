/*
* Copyright (c) 2016 Yunding Network Technology(Beijing) Co., Ltd
* All Rights Reserved.
* Confidential and Proprietary - Yunding Network Technology.
* VERSION v1.0
*
*/

#include <string.h>
#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
/*
* DEFINES CONFIGURE
****************************************************************************************
*/
#define     SHOW_DEBUG_LOG           (1)

/*
* DEFINES STURATE LOG
****************************************************************************************
*/
#define     uchar               unsigned char
#define     uint                unsigned int
#define LOG_PRINT(format, ...)               \
    do                                       \
    {                                        \
        printf(format, ##__VA_ARGS__);       \
    }while(0)

#if (SHOW_DEBUG_LOG == 1)
    #define LOG(format, ...)             LOG_PRINT(format, ##__VA_ARGS__)
#else
    #define LOG(format, ...)
#endif

/*
* DEFINES
****************************************************************************************
*/
#define PUBLIC_KEY_SIZE                 (64)
#define SIGNATURE_SIZE                  (64)
#define PRIVATE_KEY_FILE_SIZE           (121)
#define SIGN_MAX_INPUT_FILE_SIZE        (4*1024)

#define PRIVATE_FILE_NAME   "ECDSA_Private_key.der"
#define PUBLIC_FILE_NAME   "ECDSA_Public_key.h"
#define HEADER_FILE_HEADER1  "#ifndef ECDSA_PUBLIC_KEY_H\r\n#define ECDSA_PUBLIC_KEY_H\r\n\r\n\r\n"
#define HEADER_FILE_HEADER2  "\r\nstatic const unsigned char ecdsa_pubkey[64] = {\r\n"
#define HEADER_FILE_HEADER3  "\r\n};\n\n"
#define HEADER_FILE_HEADER4  "\r\n\r\n\r\n\r\n#endif;\r\n"

/*
* STATIC
****************************************************************************************
*/
typedef enum 
{
    TITLE,
    PARAM_ERROR,
    HELP,
} log_type_t;

//存放公私秘钥签名摘要
static uchar buf_PublicKey[1024] = {0,};
static uchar buf_PrivateKey[1024] = {0,};


/**
****************************************************************************************
* @brief
* @param[in] 
* @return
****************************************************************************************
*/
void hex_to_str(uchar *dest, uchar *source, int sourceLen)
{
    char ddl,ddh;
    int i;

    for (i=0; i<sourceLen; i++)
    {
        ddh = 48 + source[i] / 16;
        ddl = 48 + source[i] % 16;
        if (ddh > 57) ddh = ddh + 7;
        if (ddl > 57) ddl = ddl + 7;
        dest[i*2] = ddh;
        dest[i*2+1] = ddl;
    }

    dest[sourceLen*2] = '\0';
}
void str_to_hex(const char* source, uchar* dest, int sourceLen)
{
    short i;
    uchar highByte, lowByte;

    for (i = 0; i < sourceLen; i += 2)
    {
        highByte = toupper(source[i]);
        lowByte  = toupper(source[i + 1]);

        if (highByte > 0x39)
            highByte -= 0x37;
        else
            highByte -= 0x30;

        if (lowByte > 0x39)
            lowByte -= 0x37;
        else
            lowByte -= 0x30;

        dest[i / 2] = (highByte << 4) | lowByte;
    }
    return ;
}

void show_hex_array(int length,uchar *hex)
{
    int i=0;
    for(i=0; i<length; i++)
    {
        if((i != 0) && (i%16 == 0))
        {
            LOG("\r\n");
        }
        LOG("0x%02X,",hex[i]);
    }
    LOG("\r\n\r\n");
}

/**
****************************************************************************************
* @brief
* @param[in] 
* @return
****************************************************************************************
*/

/* hash ppaintext */
uint get_plaintext_hash(uchar *plaintext,uint length, uchar *hash)
{
    int i= 0;
    uchar digest_temp[32] = {0,};
    uint degest_temp_len = 0;    

    printf("========================== %d \n",length);
    show_hex_array(length,plaintext);

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(md_ctx);
    EVP_DigestInit(md_ctx, EVP_sha256());
    EVP_DigestUpdate(md_ctx, (void*)plaintext,length);
    EVP_DigestFinal(md_ctx, digest_temp, &degest_temp_len);
    memcpy(hash,digest_temp,32);
    printf("Input file hash HEX : \n");
    show_hex_array(32,hash);
    return 0;
}

/* generate a ECDSA key pair */
uint generate_ecdsa_keypair(uchar *privatekey_file_name,uchar *publickey_file_name)
{
    int i;
    EC_KEY *ec_key;
    EC_GROUP *ec_group;
    uchar *pp_PublicKey;
    uchar *pp_PrivateKey;
    uchar ret_len = 0;  
    uchar buf_PublicKey_w[1024] = {0,};
    uchar buf_PrivateKey_w[1024] = {0,};  
    uchar hex_byte_buf[10] = {0,};    

    //new key struct
    if ((ec_key = EC_KEY_new()) == NULL)
    {
        printf("Error:EC_KEY_new()\n");
        return 1;
    }

    //set ecsda curve name
    if ((ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL)
    {
        printf("Error:EC_GROUP_new_by_curve_name()\n");
        EC_KEY_free(ec_key);
        return 1;
    }

    //set ecdsa group param to ec_key struct
    int ret;
    ret = EC_KEY_set_group(ec_key,ec_group);
    if(ret!=1)
    {
        printf("Error:EC_KEY_set_group()\n");
        return 1;
    }

    //generate key pair to ec_key struct
    if (!EC_KEY_generate_key(ec_key))
    {
        printf("Error:EC_KEY_generate_key()\n");
        EC_KEY_free(ec_key);
        return 1;
    }

    #if 1
    //get private key form ec_key struct
    pp_PrivateKey = buf_PrivateKey;
    ret_len = i2d_ECPrivateKey(ec_key,&pp_PrivateKey);
    if (!ret_len)
    {
        printf("Error:i2d_ECPrivateKey()\n");
        EC_KEY_free(ec_key);
        return 1;
    }

    //show private raw data
    LOG("ECDSA Private key DER HEX: %d",ret_len);
    show_hex_array(ret_len,buf_PrivateKey);
    
    LOG("ECDSA Private key HEX: 64");
    show_hex_array(32,&buf_PrivateKey[7]);

    
    //storage private key to DER file
    FILE* fp_private=NULL;
    if(!(fp_private=fopen(privatekey_file_name,"w+")))
    {
        printf("Open private key file fail");
        fclose(fp_private);
        return 1;
    }
    fwrite(buf_PrivateKey,1,(ret_len),fp_private);
    fclose(fp_private);
    #endif

    #if 1
    //get public key form ec_key strcut
    pp_PublicKey = buf_PublicKey;
    ret_len = i2o_ECPublicKey(ec_key,&pp_PublicKey);
    if (!ret_len)
    {
        printf("Error:i2o_ECPublicKey()\n");
        EC_KEY_free(ec_key);
        return 1;
    }
    
    //drop first byte,first byte means pubkey zip or not
    ret_len = ret_len-1; 
    memcpy(buf_PublicKey,&buf_PublicKey[1],ret_len);
      
    //show public key raw data
    LOG("ECDSA public key HEX: : %d ",ret_len);
    show_hex_array(ret_len,buf_PublicKey);
    
    //storage public key to header file
    FILE* fp_public=NULL;
    if(!(fp_public=fopen(publickey_file_name,"w+")))
    {
        fclose(fp_public);
        LOG("Open public key file fail");
        return 1;
    }
    
    //format header file
    fwrite(HEADER_FILE_HEADER1,1,(sizeof(HEADER_FILE_HEADER1)),fp_public);
    fwrite(HEADER_FILE_HEADER2,1,(sizeof(HEADER_FILE_HEADER2)),fp_public);
    for (i=0; i<ret_len; i++)
    {
        //write every byte to header file
        memset(hex_byte_buf,0x00,10);
        if(i%8 == 0)
        {
            fwrite("\r\n",1,(2),fp_public);
        }
        sprintf(hex_byte_buf,"0x%02x",buf_PublicKey[i]);
        fwrite(hex_byte_buf,1,(4),fp_public);
        if(i != ret_len-1)
        {
            fwrite(",",1,(1),fp_public);
        }
        else
        {
            fwrite("\r\n",1,(2),fp_public);
        }
    }
    fwrite(HEADER_FILE_HEADER3,1,(sizeof(HEADER_FILE_HEADER3)),fp_public);
    fwrite(HEADER_FILE_HEADER4,1,(sizeof(HEADER_FILE_HEADER4)),fp_public); 
    fclose(fp_public);
    #endif

    EC_KEY_free(ec_key);
    LOG("Add a New Key Success \r\n");
    return 0;
}


/* gengrate ecdsa sginature */
uchar get_ecdsa_signature(uchar *private_key,int privkey_len,uchar *plaintext,int palin_len,uchar *signature)
{
    int i=0;
    EC_KEY *ec_key = NULL;
    uchar hash_temp[32] = {0,};
    uchar sign_der_temp[512] = {0,};
    uint sign_der_temp_len = 0;     

    //compute plaintext hash    
    get_plaintext_hash(plaintext,palin_len,hash_temp);

    uchar *pp = (uchar*)buf_PrivateKey;
    memcpy(buf_PrivateKey,private_key,privkey_len);

    
    LOG("ECDSA Signature Input PrivateKey: %d \r\n",privkey_len);
    show_hex_array(privkey_len,buf_PrivateKey);
    
    //set private key
    ec_key = d2i_ECPrivateKey(&ec_key, (const uchar**)&pp, privkey_len);
    if ( ec_key == NULL)
    {
        printf("Error:d2i_ECPrivateKey()\n");
        return 1;
    }

    //compute signature
    if (!ECDSA_sign(0,hash_temp, 32, sign_der_temp,&sign_der_temp_len,ec_key))
    {
        printf("Error:ECDSA_sign()\n");
        EC_KEY_free(ec_key);
        return 1;
    }

    //show sign der raw data
    LOG("ECDSA signature DER : %d\r\n",sign_der_temp_len);
    show_hex_array(sign_der_temp_len,sign_der_temp);

    #if 0
    memcpy(signature,sign_der_temp,sign_der_temp_len);
    #endif
    
    //get sign raw data
    #if 0
    if(0x20 == sign_der_temp[3])
    {
        for(i=0;i<32;i++)
        {
            signature[i] = sign_der_temp[31+4-i];
        }
        if(0x20 == sign_der_temp[37])
        {
            for(i=0;i<32;i++)
            {
                signature[i+32] = sign_der_temp[69-i];
            }
        }
        else if(0x21 == sign_der_temp[37])
        {
            for(i=0;i<32;i++)
            {
                signature[i+32] = sign_der_temp[70-i];
            }

        }
    }
    else if(0x21 == sign_der_temp[3])
    {
        for(i=0;i<32;i++)
        {
            signature[i] = sign_der_temp[31+5-i];//ASN1头如0x30, 0x46, 0x02, 0x21, 0x00,
        }
        if(0x20 == sign_der_temp[38])
        {
            for(i=0;i<32;i++)
            {
                signature[i+32] = sign_der_temp[70-i];
            }
        }
        else if(0x21 == sign_der_temp[38])
        {
            for(i=0;i<32;i++)
            {
                signature[i+32] = sign_der_temp[71-i];
            }
        }
    }
    #endif

    //get sign raw data
    #if 1
    if(0x20 == sign_der_temp[3])
    {
        for(i=0;i<32;i++)
        {
            signature[i] = sign_der_temp[4+i];
        }
        if(0x20 == sign_der_temp[37])
        {
            for(i=0;i<32;i++)
            {
                signature[i+32] = sign_der_temp[38+i];
            }
        }
        else if(0x21 == sign_der_temp[37])
        {
            for(i=0;i<32;i++)
            {
                signature[i+32] = sign_der_temp[39+i];
            }

        }
    }
    else if(0x21 == sign_der_temp[3])
    {
        for(i=0;i<32;i++)
        {
            signature[i] = sign_der_temp[5+i];//ASN1头如0x30, 0x46, 0x02, 0x21, 0x00,
        }
        if(0x20 == sign_der_temp[38])
        {
            for(i=0;i<32;i++)
            {
                signature[i+32] = sign_der_temp[39+i];
            }
        }
        else if(0x21 == sign_der_temp[38])
        {
            for(i=0;i<32;i++)
            {
                signature[i+32] = sign_der_temp[40+i];
            }
        }
    }
    #endif

    //show sign der raw data
    LOG("ECDSA signature raw data :  64\r\n");
    show_hex_array(64,signature);
    
    return 0;
}


/* 验证函数 */
int verify_ecdsa_signature(uchar *signature,uchar *publickey,uchar *plaintext, int plain_len)
{
    int ret = 0;
    int i = 0;
    EC_KEY *ec_key = NULL;
    EC_GROUP *ec_group;
    uchar hash_temp[32] = {0,};
    uchar *pp = (uchar*)buf_PublicKey;
    memset(&buf_PublicKey[0],0x04,1);
    memcpy(&buf_PublicKey[1],publickey,PUBLIC_KEY_SIZE);

    LOG("ECDSA verify_ecdsa_signature: %d \r\n",PUBLIC_KEY_SIZE+1);
    for (i=0; i<PUBLIC_KEY_SIZE+1; i++)
    {
        LOG("%02X",buf_PublicKey[i]);
    }
    LOG("\r\n");

    //compute plaintext hash    
    get_plaintext_hash(plaintext,plain_len,hash_temp);
    
    if ((ec_key = EC_KEY_new()) == NULL)
    {
        printf("Error:EC_KEY_new()\n");
        return -1;
    }
    
    if ((ec_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL)
    {
        printf("Error:EC_GROUP_new_by_curve_name()\n");
        EC_KEY_free(ec_key);
        return -1;
    }

    // 设置密钥参数
    ret=EC_KEY_set_group(ec_key,ec_group);
    if(ret!=1)
    {
        printf("Error:EC_KEY_set_group\n");
        EC_KEY_free(ec_key);
        return -1;
    }

    // 导入公钥
    ec_key = o2i_ECPublicKey(&ec_key,(const uchar**)&pp,PUBLIC_KEY_SIZE+1);
    if (ec_key == NULL)
    {
        printf("Error：o2i_ECPublicKey\n");
        EC_KEY_free(ec_key);
        return 0;
    }

    // 验证签名
    ret = ECDSA_verify(0,hash_temp, 32, signature, 72 ,ec_key);
    LOG("ECDSA_verify ret = %d \n", ret);
    
    EC_KEY_free(ec_key);
    return ret;
}




void log_show(uchar type)
{
    switch(type)
    {
        case PARAM_ERROR:
        {
            printf("Invalid Parameter !\r\n");
            break;
        }
        
        case HELP:
        {
            printf("*********ECDSA Signature Tool*********\r\n");
            printf("Usage:\r\n");
            printf("For help : ecdsa_sign_tool help\r\n");
            printf("For generate a ecdsa key pair : ecdsa_sign_tool genkeypair [private key DER file] [public key header file]\r\n");
            printf("For generate file signature : ecdsa_sign_tool gensign [private key file] [input file] [output signature file]\r\n");
            printf("*********ECDSA Signature Tool*********\r\n");
            break;
        }
        
        case TITLE:
        {
            printf("* ECDSA Signature Tool\r\n");
            printf("* Copyright (c) 2016 Yunding Network Technology(Beijing) Co., Ltd\r\n");
            printf("* All Rights Reserved.\r\n");
            printf("* Confidential and Proprietary - Yunding Network Technology.\r\n");
            printf("* VERSION v1.0\r\n");
            break;
        }
        
        case 4:
        {
            
            break;
        }
        
        default:
        {
            
            break;
        }
    }

    
}
/**
****************************************************************************************
* @brief
* @param[in] 
* @return
****************************************************************************************
*/
void main(int argc,char** argv)
{
    #if 1
    LOG("input param count : %d \n", argc);
    switch(argc)
    {
        case 1:
        {
            log_show(TITLE);
            break;
        }
            
        case 2:
        {
            //help
            if(memcmp(argv[1],"help",5) == 0)
            {
                log_show(HELP);
            }
            else
            {
                log_show(PARAM_ERROR);
            }
            
            break;
        }
        
        case 4:
        {
            //generate keypiar
            if(memcmp(argv[1],"genkeypair",11) == 0)
            {
                if(generate_ecdsa_keypair(argv[2],argv[3]) == 0)
                {
                    printf("Generate ecdsa key pair success!\r\n");
                }
                else
                {
                    printf("Generate ecdsa key pair fail !\r\n");
                }
            }
            else
            {
                log_show(PARAM_ERROR);
            }
            
            break;
        }
        
        case 5:
        {
            //generate key signature
            if(memcmp(argv[1],"gensign",8) == 0)
            {
                int file_len=0;
                FILE* p_private=NULL;
                FILE* p_bin_file=NULL;
                FILE* p_out_file=NULL;
                uchar temp_privkey[256] = {0,};
                uchar temp_buffer[4*1024] = {0,};
                uchar temp_sign[64] = {0,};
                uchar temp_sign_str[512] = {0,};
                
                //open file
                printf("Private key file name : %s \r\n",argv[2]);
                if(!(p_private=fopen(argv[2],"rt")))
                {
                    fclose(p_private);
                    printf("open private key file error \r\n");
                    break;
                }
                printf("Input file Name : %s \r\n",argv[3]);
                if(!(p_bin_file=fopen(argv[3],"rt")))
                {
                    fclose(p_bin_file);
                    printf("open input file error \r\n");
                    break;
                }
                printf("Output signature file name : %s \r\n",argv[4]);
                if(!(p_out_file=fopen(argv[4],"w+")))
                {
                    fclose(p_out_file);
                    printf("open output sign file error \r\n");
                    break;
                }

                //read private key
                fread(temp_privkey,1,(PRIVATE_KEY_FILE_SIZE),p_private);
                //read intpu file 
                file_len = fread(temp_buffer,1,SIGN_MAX_INPUT_FILE_SIZE,p_bin_file);
                LOG("Signature intpu file data :  %d\n",file_len);
                show_hex_array(file_len,temp_buffer);

                //generate signature
                get_ecdsa_signature(temp_privkey,PRIVATE_KEY_FILE_SIZE,temp_buffer,file_len,temp_sign);

                //write to file
                hex_to_str(temp_sign_str, temp_sign, (SIGNATURE_SIZE*2));
                fwrite(temp_sign_str,1,(SIGNATURE_SIZE*2),p_out_file);
                printf("Generate file signature success!\r\n");

                fclose(p_private);
                fclose(p_bin_file);
                fclose(p_out_file);
            }
            else
            {
                log_show(PARAM_ERROR);
            }
            break;
        }
        
        default:
        {
            log_show(PARAM_ERROR);
            break;
        }
    }
    #endif

        #if 0
        LOG("====================================TEST START \r\n");
        generate_ecdsa_keypair();

        #if 1
        int ret = 0;
        uchar temp_privkey[256] = {0,};
        uchar temp_test[] = "asdfjasljdfalskdf";
        uchar temp_sign[128] = {0,};
        uchar temp_pubkey[64] = {
0xa6,0x3b,0x94,0x22,0x5b,0x9c,0x7f,0xc9,
0xb8,0x3c,0xba,0xc1,0xb0,0x0c,0x7f,0x90,
0x72,0x2f,0xc7,0xed,0xc8,0xc6,0x8f,0xce,
0x47,0xc9,0x6e,0x99,0x39,0x6b,0x78,0x6e,
0xe6,0x30,0xff,0xbe,0x86,0xc4,0x13,0x19,
0xe6,0xb0,0xef,0x70,0x1a,0xc2,0x5d,0x66,
0xef,0x28,0x51,0x4e,0x61,0x39,0xa6,0x07,
0xd8,0xd4,0xfb,0x94,0x41,0x50,0x28,0x83
        };
        uchar temp_hash[64];
        
        FILE* p_private=NULL;
        if(!(p_private=fopen(PRIVATE_FILE_NAME,"rt")))
        {
            LOG("Signature Fail, User or Password is Error: Segmentation fault (core dumped)");
        }
        fread(temp_privkey,1,(121),p_private);

        get_ecdsa_signature(temp_privkey,121,temp_test,10,temp_sign);

    
        ret = verify_ecdsa_signature(temp_sign,temp_pubkey,temp_test,10);
        LOG("============================verify : %d ",ret);   
        #endif
        #endif


        #if 0
        LOG("====================================TEST START \r\n");

        uchar temp_test[10] = {0x61,0x73,0x64,0x66,0x6A,0x61,0x73,0x6C,0x6A,0x64,};
        uchar temp_hash[64] = {0,};
        
        FILE* p_private=NULL;
        if(!(p_private=fopen("ppppptest.bin","w+")))
        {
            LOG("Signature Fail, User or Password is Error: Segmentation fault (core dumped)");
        }
        fwrite(temp_test,1,(10),p_private);
            
        get_plaintext_hash(temp_test,10,temp_hash);
        
        #endif
}
