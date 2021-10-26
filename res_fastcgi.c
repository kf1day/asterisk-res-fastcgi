#include <string.h>
#include <sys/un.h>

#ifndef KEEPALIVE
#define KEEPALIVE 1
#endif

#if KEEPALIVE
#define PACKET_ID id
#else
#define PACKET_ID 1
#endif


#define AST_MODULE "res_fastcgi"
#define AST_MODULE_SELF_SYM res_fastagi


#include "asterisk.h"

#include "asterisk/config.h"
#include "asterisk/module.h"
#include "asterisk/logger.h"
#include "asterisk/manager.h"

#define FCGI_BUFFER_SIZE 0x2000
#define FCGI_SCRIPT_SIZE 0x0100

#define FCGI_CONFIG AST_MODULE".conf"
#define FCGI_SOCKET "/var/run/asterisk/php-fpm.sock"
#define FCGI_SCRIPT "/var/lib/asterisk/manager.php"

typedef enum {
	FCGI_BEGIN = 1,
	FCGI_ABORT,
	FCGI_END,
	FCGI_PARAMS,
	FCGI_STDIN,
	FCGI_STDOUT,
	FCGI_STDERR,
	FCGI_DATA,
	FCGI_GET_VALUES,
	FCGI_GET_VALUES_RESULT,
	FCGI_UNKNOWN_TYPE,
	FCGI_MAXTYPE = 11
} FCGI_TYPE;

typedef enum {
	FCGI_RESPONDER = 1,
	FCGI_AUTHORIZER,
	FCGI_FILTER
} FCGI_ROLE;




#define _B0( C ) ( ( C >>  0 ) & 0xff )
#define _B1( C ) ( ( C >>  8 ) & 0xff )
#define _B2( C ) ( ( C >> 16 ) & 0xff )
#define _B3( C ) ( ( C >> 24 ) | 0x80 )


static int sock_stream, res;
static struct sockaddr_un sock_options = { 0 };
static struct manager_custom_hook fcgi_hook = { 0 };
static char buffer[FCGI_BUFFER_SIZE], script_filename[FCGI_SCRIPT_SIZE] = FCGI_SCRIPT;


static uint8_t fcgi_set_header( char *buf, FCGI_TYPE type, uint16_t req_id, uint16_t len ) {
	uint8_t pad = ~( len - 1 ) & 7;

	buf[0] = 1;					//version
	buf[1] = type;				//type
	buf[2] = _B1( req_id );		//request ID B1
	buf[3] = _B0( req_id );		//request ID B0
	buf[4] = _B1( len );		//content length B1
	buf[5] = _B0( len );		//content length B0
	buf[6] = pad;				//padding length
	buf[7]	= 0;				//reserved

	return pad;
}

static void fcgi_get_header( char *buf, char **type, int *req_id, uint16_t *len, char **padding ) {

	*type = buf+1;
	*req_id = ( buf[2] << 8 ) | buf[3];
	*len = buf[4] << 8 | buf[5];
	*padding = buf+6;
}

static void fcgi_set_options( char *buf, FCGI_ROLE role, _Bool keepalive ) {

	*buf++	= (uint8_t) _B1( role );		// roleB1
	*buf++	= (uint8_t) _B0( role );		// roleB0
	*buf++	= keepalive;					// keep-alive flag
	memset( buf, 0, 5 );
}

static int fcgi_set_keyval( char *buf, const char *key, const char *val ) {
	
	int klen, vlen;
	
	klen = strlen( key );
	vlen = strlen( val );

	if ( klen < 0 || vlen < 0 ) return 0;

	res = 0;
	
	if ( klen >> 7 ) {
		*buf++ = (uint8_t) _B3( klen );
		*buf++ = (uint8_t) _B2( klen );
		*buf++ = (uint8_t) _B1( klen );
		*buf++ = (uint8_t) _B0( klen );
		res += 4;
	} else {
		*buf++ = (uint8_t) _B0( klen );
		res += 1;
	}

	if ( vlen >> 7 ) {
		*buf++ = (uint8_t) _B3( vlen );
		*buf++ = (uint8_t) _B2( vlen );
		*buf++ = (uint8_t) _B1( vlen );
		*buf++ = (uint8_t) _B0( vlen );
		res += 4;
	} else {
		*buf++ = (uint8_t) _B0( vlen );
		res += 1;
	}
	
	memcpy( buf, key, klen );
	buf += klen;
	memcpy( buf, val, vlen );

	return res + klen + vlen;
}

static int fcgi_connect( char reconnect ) {

	if ( reconnect && sock_stream ) {
		read( sock_stream, buffer, FCGI_BUFFER_SIZE );
		shutdown( sock_stream, SHUT_RDWR );
		close( sock_stream );
	}
	sock_stream = socket( AF_UNIX, SOCK_STREAM, 0 );
	if ( !sock_stream ) {
		ast_log( AST_LOG_ERROR, "Unable to create socket: %s\n", strerror( errno ) );
		return -1;
	}
	res = connect( sock_stream, ( struct sockaddr* )&sock_options, sizeof( struct sockaddr_un ) );
	if ( res < 0 ) {
		ast_log( AST_LOG_ERROR, "Cannot connect to FPM: %s: %s\n", sock_options.sun_path, strerror( errno ) );
		return -1;
	}
	return 0;
}

static int fcgi_worker( int category, const char *event, char *body ) {
	#if KEEPALIVE
	static uint16_t id = 0;
	#endif
	uint16_t len;
	char *pos, *end;

	len = 0;

	#if KEEPALIVE
	id++;
	#endif

	fcgi_set_header( buffer+0x00, FCGI_BEGIN, PACKET_ID, 0x08 );
	fcgi_set_options( buffer+0x08, FCGI_RESPONDER, KEEPALIVE );
	// skip bytes for further FCGI_PARAMS header here
	len += fcgi_set_keyval( buffer+0x18+len, "SCRIPT_FILENAME", script_filename );
	len += fcgi_set_keyval( buffer+0x18+len, "REQUEST_METHOD", "GET" );

	pos = strstr( body, ": " );
	while( pos && ( len + 0x28 < FCGI_BUFFER_SIZE ) ) {
		*pos = 0;
		end = strstr( pos+2, "\r\n" );
		if ( end == NULL ) break;
		*end = 0;
		
		len += fcgi_set_keyval( buffer+0x18+len, body, pos+2 );
		body = end+2;
		
		pos = strstr( body, ": " );
	}

	res = fcgi_set_header( buffer+0x10, FCGI_PARAMS, PACKET_ID, len );

	for( ; res > 0; res-- ) {
		buffer[0x18+len] = 0;
		len++;
	}
	fcgi_set_header( buffer+0x18+len, FCGI_PARAMS, PACKET_ID, 0x00 );
	fcgi_set_header( buffer+0x20+len, FCGI_STDIN, PACKET_ID, 0x00 );
	len += 0x28; // including bytes of heading and trailing headers

	#if KEEPALIVE
	res = write( sock_stream, buffer, len );
	if ( res < 0 ) {
		ast_debug( 1, "Failed to write: %s, reconnecting...\n", strerror( errno ) );
		fcgi_connect( 1 );
		res = write( sock_stream, buffer, len );
	}
	#else
	fcgi_connect( 0 );
	res = write( sock_stream, buffer, len );
	#endif
	ast_debug( 2, "EOR #%d, send: %d\n", PACKET_ID, res );
	if ( res < 0 ) {
		ast_log( AST_LOG_ERROR, "Failed to write: %s\n", strerror( errno ) );
	} else {
		res = 0;
		do {
			len = read( sock_stream, buffer, FCGI_BUFFER_SIZE );
			res += len;
		} while ( len == FCGI_BUFFER_SIZE );

		ast_debug( 2, "EOR #%d, recv: %d\n", PACKET_ID, res );
		if ( res >  FCGI_BUFFER_SIZE ) {
			ast_log( AST_LOG_NOTICE, "FCGI result too long\n" );
		} else {
			fcgi_get_header( buffer, &pos, &res, &len, &end );
			if ( *pos == FCGI_STDOUT && res == PACKET_ID ) {
				buffer[0x08+len] = 0;
				ast_debug( 3, "%s\n", buffer + 0x08 );
			}
		}

	}
	#if KEEPALIVE
	#else
	shutdown( sock_stream, SHUT_RDWR );
	close( sock_stream );
	#endif

	return 0;
}

static int load_module( void ) {
	struct ast_config *cfg;
	struct ast_flags cfg_flags = { 0 };
	const char *tmp;

	cfg = ast_config_load( FCGI_CONFIG, cfg_flags );

	if ( cfg == NULL || cfg == CONFIG_STATUS_FILEINVALID ) {
		ast_log( AST_LOG_ERROR, "Unable to load config: " FCGI_CONFIG "\n" );
		return AST_MODULE_LOAD_DECLINE;
	}


	sock_options.sun_family = AF_UNIX;
	if ( ast_variable_browse( cfg, "global" ) ) {
		tmp = ast_variable_retrieve( cfg, "global", "socket" );
		if ( tmp ) {
			strcpy( sock_options.sun_path, tmp );
		} else {
			ast_log( AST_LOG_NOTICE, "FCGI server socket not specified. Using default: " FCGI_SOCKET "\n" );
			strcpy( sock_options.sun_path, FCGI_SOCKET );
		}

		tmp = ast_variable_retrieve( cfg, "global", "script" );
		if ( tmp ) {
			if ( strlen( tmp ) < FCGI_SCRIPT_SIZE ) {
				strcpy( script_filename, tmp );
			} else {
				ast_log( AST_LOG_WARNING, "FCGI script path is too long. Using default: " FCGI_SCRIPT "\n" );
			}
		} else {
			ast_log( AST_LOG_NOTICE, "FCGI script not specified. Using default: " FCGI_SCRIPT "\n" );
		}
	} else {
		ast_log( AST_LOG_WARNING, "Global section not found, using defaults\n" );
		strcpy( sock_options.sun_path, FCGI_SOCKET );
	}
	ast_config_destroy( cfg );

	#if KEEPALIVE
	fcgi_connect( 0 );
	#endif

	fcgi_hook.helper = fcgi_worker;

	ast_manager_register_hook( &fcgi_hook );
	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module( void ) {

	ast_manager_unregister_hook( &fcgi_hook );
	#if KEEPALIVE
	/*
	fcgi_set_header( buffer+0x00, FCGI_BEGIN, 0, 0x08 );
	fcgi_set_options( buffer+0x08, FCGI_RESPONDER, 0 );
	fcgi_set_header( buffer+0x10, FCGI_ABORT, 0, 0x08 );
	write( sock_stream, buffer, 0x18 );
	do {
		res = read( sock_stream, buffer, FCGI_BUFFER_SIZE );
	} while ( res == FCGI_BUFFER_SIZE );
	shutdown( sock_stream, SHUT_RDWR );
	*/
	close( sock_stream );
	#endif
	return 0;
}


AST_MODULE_INFO_STANDARD_EXTENDED( ASTERISK_GPL_KEY, "FastCGI Resource Module" );
