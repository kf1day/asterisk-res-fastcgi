#include <string.h>
#include <sys/un.h>


#define AST_MODULE "res_fastcgi"
#define AST_MODULE_SELF_SYM res_fastagi


#include "asterisk.h"

#include "asterisk/config.h"
#include "asterisk/module.h"
#include "asterisk/logger.h"
#include "asterisk/manager.h"

#define FCGI_MSG_SZ 0x4000

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


static uint8_t fcgi_set_header( char *msg, FCGI_TYPE type, int req_id, int len ) {
	uint8_t pad = ( 8 - ( len % 8 ) ) % 8;

	*msg++	= 1;							//version
	*msg++	= (uint8_t) type;				//type
	*msg++	= (uint8_t) _B1( req_id );		//request ID B1
	*msg++	= (uint8_t) _B0( req_id );		//request ID B0
	*msg++	= (uint8_t) _B1( len );			//content length B1
	*msg++	= (uint8_t) _B0( len );			//content length B0
	*msg++	= pad;							//padding length
	*msg++	= 0;							//reserved

	return pad;
}

static void fcgi_set_options( char *msg, FCGI_ROLE role, uint8_t keepalive ) {

	*msg++	= (uint8_t) _B1( role );		//roleB1
	*msg++	= (uint8_t) _B0( role );		//roleB0
	*msg++	= ( ( keepalive ) ? 1 : 0 );	//flags
	*msg++	= 0;
	*msg++	= 0;
	*msg++	= 0;
	*msg++	= 0;
	*msg++	= 0;


}

static int fcgi_keyval( char *msg, const char *key, const char *val ) {
	
	int klen, vlen, offset = 0;
	
	klen = strlen( key );
	vlen = strlen( val );
	
	if ( klen < 0x80 ) {
		*msg++ = (uint8_t) _B0( klen );
		offset++;
	} else {
		*msg++ = (uint8_t) _B3( klen );
		*msg++ = (uint8_t) _B2( klen );
		*msg++ = (uint8_t) _B1( klen );
		*msg++ = (uint8_t) _B0( klen );
		offset += 4;
	}

	if ( vlen < 0x80 ) {
		*msg++ = (uint8_t) _B0( vlen );
		offset++;
	} else {
		*msg++ = (uint8_t) _B3( vlen );
		*msg++ = (uint8_t) _B2( vlen );
		*msg++ = (uint8_t) _B1( vlen );
		*msg++ = (uint8_t) _B0( vlen );
		offset += 4;
	}
	
	memcpy( msg, key, klen );
	msg += klen;
	
	memcpy( msg, val, vlen );
	msg += vlen;

	offset += klen + vlen;

	return offset;
}


static int sock_stream, initial_packet_len;
static struct sockaddr_un sock_options = { 0 };
static struct manager_custom_hook fcgi_hook = { 0 };
static char fcgi_request[FCGI_MSG_SZ], fcgi_responce[FCGI_MSG_SZ];


static int fcgi_connect( char reconnect ) {
	int res;
	
	if ( reconnect && sock_stream ) {
		shutdown( sock_stream, SHUT_RDWR );
		read( sock_stream, fcgi_responce, FCGI_MSG_SZ );
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
	static int id = 1;
	
	char *pos, *end;
	int res, len = initial_packet_len;
	
	
	fcgi_set_header( fcgi_request+0x00, FCGI_BEGIN, id, 0x08 );

	pos = strstr( body, ": " );
	while( pos ) {
		*pos = 0;
		end = strstr( pos+2, "\r\n" );
		*end = 0; // #TODO check if null
		
		len += fcgi_keyval( fcgi_request+0x18+len, body, pos+2 );
//		ast_debug( 0, "%s => %s\n", body, pos+2 );
		body = end+2;
		
		pos = strstr( body, ": " );
	}
	
	res = fcgi_set_header( fcgi_request+0x10, FCGI_PARAMS, id, len );
	for( ; res > 0; res-- ) {
		fcgi_request[0x18+len] = 0;
		len++;
	}
	fcgi_set_header( fcgi_request+0x18+len, FCGI_PARAMS, id, 0x00 );
	fcgi_set_header( fcgi_request+0x20+len, FCGI_STDIN, id, 0x00 );
	len += 0x28;
	res = write( sock_stream, fcgi_request, len );
	
	if ( res < 0 ) {
		ast_debug( 1, "Failed to write: %s, reconnecting...\n", strerror( errno ) );
		res = fcgi_connect( 1 );
		if ( res < 0 ) {
			ast_log( AST_LOG_ERROR, "Failed to write: %s, giving up...\n", strerror( errno ) );
		} else {
			write( sock_stream, fcgi_request, len );
		}
	}
	
	res = read( sock_stream, fcgi_responce, FCGI_MSG_SZ );
	ast_debug( 2, "EOR #%d, write: %d, read: %d\n", id, len, res );
	
	id++;
	return 0;
}

/* partially filling up packet data

xxxx xxxx | 0x00 header: dynamic, set each time in "fcgi_worker()"
xxxx xxxx | 0x08 options: static, set once in "load_module()"
xxxx xxxx | 0x10 data header: dynamic, set each time in "fcgi_worker()"
xxxx xxxx | 0x18 data: set up "SCRIPT_FILENAME", "GATEWAY_INTERFACE", "REQUEST_METHOD", keep length in "initial_packet_len"
...       | ... other data, set each time in "fcgi_worker()"
xxxx xxxx | 0x18 + len + pad: FCGI_PARAMS header, set each time in "fcgi_worker()"
xxxx xxxx | 0x20 + len + pad: FCGI_PARAMS header, set each time in "fcgi_worker()"

*/

static int load_module( void ) {
	struct ast_config *cfg;
	struct ast_flags cfg_flags = { 0 };
	const char *tmp;
	
//	memset( &sock_options, 0, sizeof( struct sockaddr_un ) );
//	memset( &fcgi_hook, 0, sizeof( struct manager_custom_hook ) );
	cfg = ast_config_load( FCGI_CONFIG, cfg_flags );
	initial_packet_len = 0;
	
	if ( cfg == NULL || cfg == CONFIG_STATUS_FILEINVALID ) {
		ast_log( AST_LOG_ERROR, "Unable to load config: " FCGI_CONFIG "\n" );
		return AST_MODULE_LOAD_DECLINE;
	}
	
	fcgi_set_options( fcgi_request+0x08, FCGI_RESPONDER, 1 );
	
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
			initial_packet_len += fcgi_keyval( fcgi_request+0x18+initial_packet_len, "SCRIPT_FILENAME", tmp );
		} else {
			ast_log( AST_LOG_NOTICE, "FCGI script not specified. Using default: " FCGI_SCRIPT "\n" );
			initial_packet_len += fcgi_keyval( fcgi_request+0x18+initial_packet_len, "SCRIPT_FILENAME", FCGI_SCRIPT );
		}
	} else {
		ast_log( AST_LOG_WARNING, "Global section not found, using defaults\n" );
		strcpy( sock_options.sun_path, FCGI_SOCKET );
		initial_packet_len += fcgi_keyval( fcgi_request+0x18+initial_packet_len, "SCRIPT_FILENAME", FCGI_SCRIPT );
	}
	ast_config_destroy( cfg );
	
	initial_packet_len += fcgi_keyval( fcgi_request+0x18+initial_packet_len, "GATEWAY_INTERFACE", "CGI/1.1" );
	initial_packet_len += fcgi_keyval( fcgi_request+0x18+initial_packet_len, "REQUEST_METHOD", "GET" );
	
	fcgi_connect( 0 );
	
	fcgi_hook.helper = fcgi_worker;
	
	ast_manager_register_hook( &fcgi_hook );
	return AST_MODULE_LOAD_SUCCESS;
}


static int unload_module( void ) {

	ast_manager_unregister_hook( &fcgi_hook );
	shutdown( sock_stream, SHUT_RDWR );
	read( sock_stream, fcgi_responce, FCGI_MSG_SZ );
	close( sock_stream );
	return 0;
}


AST_MODULE_INFO_STANDARD_EXTENDED( ASTERISK_GPL_KEY, "FastCGI Resource Module" );
