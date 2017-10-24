#include <string.h>
#include <sys/un.h>
#include "asterisk.h"

#define AST_MODULE "res_fastcgi"

ASTERISK_FILE_VERSION(__FILE__, "$Revision$")

#include "asterisk/config.h"
#include "asterisk/module.h"
#include "asterisk/logger.h"
#include "asterisk/manager.h"


//AST_MUTEX_DEFINE_STATIC(fcgi_lock);


#define FCGI_MSG_SZ 0x4000
#define FCGI_HEAD_SZ 0x08

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


static uint8_t fcgi_set_header( char **msg, FCGI_TYPE type, int req_id, int len ) {
	uint8_t pad = ( FCGI_HEAD_SZ - ( len % FCGI_HEAD_SZ ) ) % FCGI_HEAD_SZ;

//	assert( len >= 0 && len <= FCGI_MSG_SZ );

	*(*msg)++	= 1;									//version
	*(*msg)++	= (uint8_t) type;					//type
	*(*msg)++	= (uint8_t) _B1( req_id );		//request ID B1
	*(*msg)++	= (uint8_t) _B0( req_id );		//request ID B0
	*(*msg)++	= (uint8_t) _B1( len );			//content length B1
	*(*msg)++	= (uint8_t) _B0( len );			//content length B0
	*(*msg)++	= pad;									//padding length
	*(*msg)++	= 0;									//reserved

	return pad;
}

static void fcgi_set_options( char **msg, FCGI_ROLE role, uint8_t keepalive ) {

//	assert( ( role >> 16 ) == 0 );

	*(*msg)++	= (uint8_t) _B1( role );		//roleB1
	*(*msg)++	= (uint8_t) _B0( role );		//roleB0
	*(*msg)++	= ( ( keepalive ) ? 1 : 0 );	//flags
	*(*msg)++	= 0;
	*(*msg)++	= 0;
	*(*msg)++	= 0;
	*(*msg)++	= 0;
	*(*msg)++	= 0;


}

static int fcgi_keyval( char *msg, const char *key, const char *val ) {
	
	int klen, vlen, offset = 0;
	
	klen = strlen( key );
	vlen = strlen( val );

//	assert( klen >= 0 && vlen >= 0 );
	
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


static int sock_stream;
static struct sockaddr_un sock_options;
static struct manager_custom_hook fcgi_hook;
static char fcgi_packet[FCGI_MSG_SZ], script_name[0x1000];


static int fcgi_connect( char reconnect ) {
	int res;
	
	if ( reconnect && sock_stream ) {
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
	static int id = 1;
	
	char *buf, *pos, *end;
	uint8_t pad;
	int len = 0;
	
	buf = fcgi_packet;
	
	fcgi_set_header( &buf, FCGI_BEGIN, id, FCGI_HEAD_SZ );
	fcgi_set_options( &buf, FCGI_RESPONDER, 1 );
	
	len += fcgi_keyval( buf+len+FCGI_HEAD_SZ, "SCRIPT_FILENAME", script_name );
	len += fcgi_keyval( buf+len+FCGI_HEAD_SZ, "REQUEST_METHOD", "GET" );

	pos = strstr( body, ": " );
	while( pos ) {
		*pos = 0;
		end = strstr( pos+2, "\r\n" );
		*end = 0; // #TODO check if null
		
		len += fcgi_keyval( buf+len+FCGI_HEAD_SZ, body, pos+2 );
		ast_debug( 3, "%s => %s\n", body, pos+2 );
		body = end+2;
		
		pos = strstr( body, ": " );
	}
	
	pad = fcgi_set_header( &buf, FCGI_PARAMS, id, len );
	buf += len;
	for( len = 0; len < pad; len++ ) {
		*buf++ = 0;
	}
	fcgi_set_header( &buf, FCGI_PARAMS, id, 0 );
	fcgi_set_header( &buf, FCGI_STDIN, id, 0 );
	len = write( sock_stream, fcgi_packet, (int)( buf - fcgi_packet ) );
	
	if ( len < 0 ) {
		ast_debug( 1, "Failed to write: %s, reconnecting...\n", strerror( errno ) );
		len = fcgi_connect( 1 );
		if ( len < 0 ) {
			ast_log( AST_LOG_ERROR, "Failed to write: %s, giving up...\n", strerror( errno ) );
		} else {
			write( sock_stream, fcgi_packet, (int)( buf - fcgi_packet ) );
		}
	}
	
	len = read( sock_stream, fcgi_packet, FCGI_MSG_SZ );
	ast_debug( 2, "EOR #%d, write: %d, read: %d\n", id, (int)( buf - fcgi_packet ), len );
	
	id++;
	return 0;
}


static int load_module( void ) {
	int res = 1;
	struct ast_config *cfg;	
	struct ast_flags cfg_flags = { 0 };
	const char *tmp;
	
	memset( &sock_options, 0, sizeof( struct sockaddr_un ) );
	memset( &fcgi_hook, 0, sizeof( struct manager_custom_hook ) );
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
			strcpy( script_name, tmp );
		} else {
			ast_log( AST_LOG_NOTICE, "FCGI script not specified. Using default: " FCGI_SCRIPT "\n" );
			strcpy( script_name, FCGI_SCRIPT );
		}
	} else {
		ast_log( AST_LOG_WARNING, "Global section not found, using defaults\n" );
		strcpy( sock_options.sun_path, FCGI_SOCKET );
		strcpy( script_name, FCGI_SCRIPT );
	}
	ast_config_destroy( cfg );
	
	res = fcgi_connect( 0 );
	if ( res < 0 ) {
		return AST_MODULE_LOAD_FAILURE;
	}

	
	fcgi_hook.helper = fcgi_worker;
	
	ast_manager_register_hook( &fcgi_hook );
	return AST_MODULE_LOAD_SUCCESS;
}


static int unload_module( void ) {

	ast_manager_unregister_hook( &fcgi_hook );
	shutdown( sock_stream, SHUT_RDWR );
	close( sock_stream );
	return 0;
}


AST_MODULE_INFO_STANDARD_EXTENDED( ASTERISK_GPL_KEY, "FastCGI Resource Module" );
