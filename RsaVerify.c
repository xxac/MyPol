//
// RSA PKCS#1 VERIFY INTERFACE
//
#include "rsa.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"

#define DATA_LEN	262144	//2048*128
#define	SAIO_TAB	'@'
#define	SAIO_OSFLAG	"-SaIoOs-"
#if 0
int RsaVerify(unsigned char *data, long size, unsigned char *N, unsigned char *E, int keylen)
{
	int rc = 0;
	rsa_context rsa;
	sha1_context ctx;
	unsigned char hash[20];
	unsigned char buf[DATA_LEN+1] = {0x00};
	long mem,idx,len;
	unsigned char temp;
	
	rsa_init( &rsa, RSA_PKCS_V15, 0 );
	rsa.len = keylen;
	mpi_read_string( &rsa.N , 16, N  );
	mpi_read_string( &rsa.E , 16, E  );
	if (rsa_check_pubkey(  &rsa ) != 0)
	{
		rsa_free( &rsa );
		return 1;
	}
	
	sha1_starts( &ctx );
	
	idx = strlen(SAIO_OSFLAG);
	mem = 0;
	while (mem <= size)
	{
		mem += DATA_LEN;
		if (mem < 10*1024*1024) // 10M
		{
			sha1_update( &ctx, data, DATA_LEN );
			data += DATA_LEN;
			continue;
		}
		//    Find the SAIO OS flag
		len = 0;
		while (len<DATA_LEN)
		{
			if (data[len]==SAIO_TAB && data[1+len+idx]==SAIO_TAB)
			{
				if (!memcmp(&data[len+1],SAIO_OSFLAG,idx)) break;
			}
			len++;
		}
		if (len==DATA_LEN)
		{
			sha1_update( &ctx, data, DATA_LEN );
			data += DATA_LEN;
		}
		else 
		{
			sha1_update( &ctx, data, len+idx+2 ); 
			break;
		}
	}
	sha1_finish( &ctx, hash );
	// reverse
	for (mem=0; mem<keylen/2; mem++)
	{
		temp = data[len+idx+2+mem];
		data[len+idx+2+mem] = data[len+idx+2+keylen-mem-1];
		data[len+idx+2+keylen-mem-1] = temp;
	}
	if( rsa_pkcs1_verify( &rsa, RSA_PUBLIC, SIG_RSA_SHA1, 20,hash, &data[len+idx+2] ) != 0 )
	{
		rc = 1;
	}

	rsa_free( &rsa );
	return rc;
}
#endif
int RsaVerify(unsigned char *data, long size, unsigned char *N, unsigned char *E, int keylen, int sha_type)
{
	int rc = 0;
	rsa_context rsa;
	sha1_context ctx_160;
	unsigned char hash_160[20];
	sha512_context ctx_512;
	unsigned char hash_512[64];
	sha256_context ctx_256;
	unsigned char hash_256[32];
	unsigned char buf[DATA_LEN+1] = {0x00};
	long mem,idx,len;
	unsigned char temp;
	
	rsa_init( &rsa, RSA_PKCS_V15, 0 );
	rsa.len = keylen;
	mpi_read_string( &rsa.N , 16, N  );
	mpi_read_string( &rsa.E , 16, E  );
	if (rsa_check_pubkey(  &rsa ) != 0)
	{
		rsa_free( &rsa );
		return 1;
	}

	if (sha_type == 160)
		sha1_starts( &ctx_160 );
	else if	(sha_type == 512)
		sha512_starts( &ctx_512,0 );
	else
		sha256_starts( &ctx_256,0 );

	
	idx = strlen(SAIO_OSFLAG);
	mem = 0;
	while (mem <= size)
	{
		mem += DATA_LEN;
		if (mem < 10*1024*1024) // 10M
		{
			if (sha_type == 160)
				sha1_update( &ctx_160, data, DATA_LEN );
			else if (sha_type == 512)
				sha512_update( &ctx_512, data, DATA_LEN );
			else
				sha256_update( &ctx_256, data, DATA_LEN );
			data += DATA_LEN;
			continue;
		}
		//    Find the SAIO OS flag
		len = 0;
		while (len<DATA_LEN)
		{
			if (data[len]==SAIO_TAB && data[1+len+idx]==SAIO_TAB)
			{
				if (!memcmp(&data[len+1],SAIO_OSFLAG,idx)) break;
			}
			len++;
		}
		if (len==DATA_LEN)
		{
			if (sha_type == 160)
				sha1_update( &ctx_160, data, DATA_LEN );
			else if (sha_type == 512)
				sha512_update( &ctx_512, data, DATA_LEN );
			else
				sha256_update( &ctx_256, data, DATA_LEN );
			data += DATA_LEN;
		}
		else 
		{
			if (sha_type == 160)
				sha1_update( &ctx_160, data, len+idx+2 );
			else if (sha_type == 512)
				sha512_update( &ctx_512, data, len+idx+2 );
			else
				sha256_update( &ctx_256, data, len+idx+2 ); 
			break;
		}
	}
	if (sha_type == 160)
		sha1_finish( &ctx_160, hash_160 );
	else if (sha_type == 512)
		sha512_finish( &ctx_512, hash_512 );
	else
		sha256_finish( &ctx_256, hash_256 );
	// reverse
	for (mem=0; mem<keylen/2; mem++)
	{
		temp = data[len+idx+2+mem];
		data[len+idx+2+mem] = data[len+idx+2+keylen-mem-1];
		data[len+idx+2+keylen-mem-1] = temp;
	}
	
	if (sha_type == 160)
	{
		if( rsa_pkcs1_verify( &rsa, RSA_PUBLIC, SIG_RSA_SHA1, 20, hash_160, &data[len+idx+2] ) != 0 )
		{
			rc = 1;
		}
	}
	else if (sha_type == 512)
	{
		if( rsa_pkcs1_verify( &rsa, RSA_PUBLIC, SIG_RSA_SHA512, 64, hash_512, &data[len+idx+2] ) != 0 )
		{
			rc = 1;
		}
	}
	else
	{
		if( rsa_pkcs1_verify( &rsa, RSA_PUBLIC, SIG_RSA_SHA256, 32, hash_256, &data[len+idx+2] ) != 0 )
		{
			rc = 1;
		}
	}

	rsa_free( &rsa );
	return rc;
}
