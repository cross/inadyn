/* Plugin for Dynu.com
 *
 * Copyright (C) 2019-2020 Simon Pilkington
 * Copyright (C) 2024 Chris Ross
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, visit the Free Software Foundation
 * website at http://www.gnu.org/licenses/gpl-2.0.html or write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

#include "plugin.h"
#include "json.h"

#define CHECK(fn)       { rc = (fn); if (rc) goto cleanup; }

#define API_HOST "api.dynu.com"
#define API_URL "/v2"

/* https://developers.cloudflare.com/api/operations/zones-get */
static const char *DYNU_DOMAIN_ID_REQUEST = "GET " API_URL "/dns/getroot/%s HTTP/1.0\r\n"	\
	"Host: " API_HOST "\r\n"		\
	"User-Agent: %s\r\n"			\
	"Accept: */*\r\n"				\
	"API-Key: %s\r\n"	\
	"Content-Type: application/json\r\n\r\n";
#if 0
/* https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-dns-record-details */	
static const char *DYNU_HOSTNAME_NAME_REQUEST_BY_ID	= "GET " API_URL "/zones/%s/dns_records/%s HTTP/1.0\r\n"	\
	"Host: " API_HOST "\r\n"		\
	"User-Agent: %s\r\n"			\
	"Accept: */*\r\n"				\
	"API-Key: %s\r\n"	\
	"Content-Type: application/json\r\n\r\n";
#endif
/* https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-list-dns-records */	
static const char *DYNU_HOSTNAME_ID_REQUEST_BY_NAME	= "GET " API_URL "/dns/record/%s?recordType=%s HTTP/1.0\r\n"	\
	"Host: " API_HOST "\r\n"		\
	"User-Agent: %s\r\n"			\
	"Accept: */*\r\n"				\
	"API-Key: %s\r\n"	\
	"Content-Type: application/json\r\n\r\n";

/* https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-create-dns-record */	
static const char *DYNU_HOSTNAME_CREATE_REQUEST	= "POST " API_URL "/dns/%s/record HTTP/1.0\r\n"	\
	"Host: " API_HOST "\r\n"		\
	"User-Agent: %s\r\n"			\
	"Accept: */*\r\n"				\
	"API-Key: %s\r\n"	\
	"Content-Type: application/json\r\n" \
	"Content-Length: %zd\r\n\r\n" \
	"%s";

/* https://developers.cloudflare.com/api/operations/dns-records-for-a-zone-update-dns-record */
static const char *DYNU_HOSTNAME_UPDATE_REQUEST	= "POST " API_URL "/dns/%s/record/%s HTTP/1.0\r\n"	\
	"Host: " API_HOST "\r\n"		\
	"User-Agent: %s\r\n"			\
	"Accept: */*\r\n"				\
	"API-Key: %s\r\n"	\
	"Content-Type: application/json\r\n" \
	"Content-Length: %zd\r\n\r\n" \
	"%s";
	
/* TODO: The API uses "hostname" in a number of places, but the syntax needs to be "nodeName" in other places.  Can that work here? */
static const char *DYNU_UPDATE_JSON_FORMAT = "{\"nodeName\":\"%s\",\"recordType\":\"%s\",\"%s\":\"%s\",\"ttl\":%li}";
static const char *DYNU_UPDATE_JSON_FORMAT_NOTTL = "{\"nodeName\":\"%s\",\"recordType\":\"%s\",\"%s\":\"%s\"}";

static const char *IPV4_RECORD_TYPE = "A";
static const char *IPV6_RECORD_TYPE = "AAAA";

static int setup    (ddns_t       *ctx,   ddns_info_t *info, ddns_alias_t *hostname);
static int request  (ddns_t       *ctx,   ddns_info_t *info, ddns_alias_t *hostname);
static int response (http_trans_t *trans, ddns_info_t *info, ddns_alias_t *hostname);

static ddns_system_t plugin = {
	.name         = "default@dynu.com",

	.setup        = (setup_fn_t)setup,
	.request      = (req_fn_t)request,
	.response     = (rsp_fn_t)response,

	/*
	 * 1.1.1.1 is chosen here due to "allow-ipv6" is default to false
	 * www.cloudflare.com would also work but is dual stack and may return ipv6 address
	 * use 1.1.1.1 to would force it return ipv4 by default
	 * see examples/cloudflare-*.conf
	 */
	.checkip_name = "1.1.1.1",
	.checkip_url  = "/cdn-cgi/trace",
	.checkip_ssl  = DDNS_CHECKIP_SSL_SUPPORTED,

	.server_name  = API_HOST,
	.server_url   = API_URL
};

/*
 * filled by the setup() callback and handed to ddns_info_t
 * for use later in the request() callback .
 */
#define MAX_ID (32 + 1)

struct dynudata {
	char domain_id[MAX_ID];
	char hostname_id[MAX_ID];
	char nodename[MAXHOSTNAMELEN];
};

static int check_response_code(int status)
{
	switch (status)
	{
	case 200:
	case 304:
		return RC_OK;
	case 400:
		logit(LOG_ERR, "HTTP 400: Cloudflare says our request was invalid. Possibly a malformed API token.");
		return RC_DDNS_RSP_NOTOK;
	case 403:
		logit(LOG_ERR, "HTTP 403: Provided API token does not have the required permissions.");
		return RC_DDNS_RSP_AUTH_FAIL;
	case 429:
		logit(LOG_WARNING, "HTTP 429: We got rate limited.");
		return RC_DDNS_RSP_RETRY_LATER;
	case 405:
		logit(LOG_ERR, "HTTP 405: Bad HTTP method; has the interface changed?");
		return RC_DDNS_RSP_NOTOK;
	case 415:
		logit(LOG_ERR, "HTTP 415: Cloudflare didn't like our JSON; has the inferface changed?");
		return RC_DDNS_RSP_NOTOK;
	default:
		logit(LOG_ERR, "Received status %i, don't know what that means.", status);
		return RC_DDNS_RSP_NOTOK;
	}
}

static int check_success(const char *json, const jsmntok_t tokens[], const int num_tokens)
{
	int i;

	for (i = 1; i < num_tokens; i++) {
		int stat;

		if (jsoneq(json, tokens + i, "statusCode") != 0)
			continue;

		if (i < num_tokens - 1 && json_int(json, tokens + i + 1, &stat) == 0)
			return ((stat / 100) == 2) ? 0 : -1;

		return -1;
	}

	if (i == num_tokens)
		logit(LOG_DEBUG, "Failed to find 'statusCode' key in JSON buffer");

	return -1;
}

static int check_success_only(const char *json)
{
	jsmntok_t *tokens;
	int num_tokens;
	int result;
	
	num_tokens = parse_json(json, &tokens);	
	if (num_tokens == -1)
		return -1;

	result = check_success(json, tokens, num_tokens);
	free(tokens);

	return result;
}

static int get_result_value(const char *json, const char *key, jsmntok_t *out_result)
{
	jsmntok_t *tokens;
	int i, num_tokens;
	
	num_tokens = parse_json(json, &tokens);
	if (num_tokens < 0) {
		logit(LOG_DEBUG, "parse_json() returned %d", num_tokens);
		return -1;
	}
	
	if (tokens[0].type != JSMN_OBJECT) {
		logit(LOG_ERR, "JSON response was not an object.");
		goto cleanup;
	}
	
	if (check_success(json, tokens, num_tokens) == -1) {
		logit(LOG_ERR, "Request was unsuccessful.");
		goto cleanup;
	}
	
	for (i = 1; i < num_tokens; i++) {
//		logit(LOG_DEBUG, "Iterating JSON searching for '%s', token is a %d at offset %ld.", key, tokens[i].type, tokens[i].start);
		if (jsoneq(json, tokens + i, key) != 0)
			continue;

		if (i < num_tokens - 1) {
			*out_result = tokens[i+1];
			free(tokens);
			return 0;
		}
	}
	
	logit(LOG_INFO, "Could not find key '%s'.", key);

cleanup:
	free(tokens);
	return -1;
}

static int json_copy_value(char *dest, size_t dest_size, const char *json, const jsmntok_t *token)
{
	size_t length;

	if (token->type != JSMN_STRING) {
		logit(LOG_DEBUG, "not a string");
		return -1;
	}
	
	length = token->end - token->start + 1;
	if (length > dest_size) {
		logit(LOG_DEBUG, "length %d is larger than dest_size %d", length, dest_size);
		return -2;
	}
	
	strlcpy(dest, json + token->start, length);

	return 0;
}

/* Issue an HTTP request, and retrieve/provide the response.  It is expected
   to be JSON, but this method doesn't ensure that. */
static int retrieve_json(char *dest, size_t dest_size, const ddns_info_t *info, char *request, size_t request_len)
{
	http_trans_t  trans;
	http_t        client;
	char         *response_buf;
	size_t        response_buflen = DDNS_HTTP_RESPONSE_BUFFER_SIZE;
	int           rc = RC_OK;

	response_buf = calloc(response_buflen, sizeof(char));
	if (!response_buf)
		return RC_OUT_OF_MEMORY;

	/* XXX Do we have to worry that this was allocated? 
	   Maybe I should just pass the context through? */
	if (dest == NULL) {
		rc = RC_INVALID_POINTER;
		goto cleanup;
	}
	memset(dest, 0, dest_size);

	CHECK(http_construct(&client));

	http_set_port(&client, info->server_name.port);
	http_set_remote_name(&client, info->server_name.name);

	client.ssl_enabled = info->ssl_enabled;
	CHECK(http_init(&client, "Json query",strstr(info->system->name, "ipv6") ? TCP_FORCE_IPV6 : TCP_FORCE_IPV4));

	trans.req = request;
	trans.req_len = request_len;
	trans.rsp = response_buf;
	trans.max_rsp_len = response_buflen - 1; /* Save place for a \0 at the end */

	logit(LOG_DEBUG, "Request:\n%s", request);
	CHECK(http_transaction(&client, &trans));

	http_exit(&client);
	http_destruct(&client, 1);

	logit(LOG_DEBUG, "Response:\n%s", trans.rsp);
	CHECK(check_response_code(trans.status));

	/* Copy the body out of the response, then free the response buf  */
	int body_len = trans.rsp_len - (trans.rsp_body - trans.rsp);
	if (dest_size < body_len+1) {
		rc = RC_BUFFER_OVERFLOW;
		goto cleanup;
	}
	memmove(dest, trans.rsp_body, body_len+1);
cleanup:
	free(response_buf);

	if (rc == RC_OK)
		logit(LOG_DEBUG, "Returning result body at %p", dest);
	return rc;
}

static int json_extract(char *dest, size_t dest_size, const char *json, const char *key)
{
	jsmntok_t     key_value;
	int           rc = RC_OK;

	// TODO: get_result_value() parses the JSON each time.  We should refactor that too.
	logit(LOG_DEBUG, "retriving '%s' from buffer at %p", key, json);
	if (get_result_value(json, key, &key_value) < 0) {
		return RC_DDNS_RSP_NOHOST;
	}
	logit(LOG_DEBUG, "found a value (type %d) (starts at %d ('%c'), ends at %d)", key_value.type, key_value.start, json[key_value.start], key_value.end);

	/* Value is often a string, but could be another primative (int).  In
	   that case, convert it to a string. 
	   nb: This prohibits later _using_ an int as an int, but... */
	if (key_value.type == JSMN_STRING) {
		if (json_copy_value(dest, dest_size, json, &key_value) < 0) {
			logit(LOG_ERR, "Key value did not fit into buffer.");
			rc = RC_BUFFER_OVERFLOW;
		}
	} else if (key_value.type == JSMN_PRIMITIVE) {
		/* Copy out the right substring, with nul term. */
		char *val_copy = strndup(json+key_value.start, key_value.end-key_value.start);
		logit(LOG_DEBUG, "Primitive for key '%s' is '%s'", key, val_copy);

		/* Verify it's an int.  Should likely later deal with boolean/null */
		if (val_copy[0] == '-' || (val_copy[0] >= '0' && val_copy[0] <= '9')) {
			long rc = strtol(val_copy, NULL, 10);
			if ((rc == LONG_MAX) || (strlen(val_copy) >= dest_size))
				rc = RC_BUFFER_OVERFLOW;
			else
				strncpy(dest,val_copy,strlen(val_copy)+1);
		} else {
			logit(LOG_DEBUG, "Primitive for key %s was not a number (%s)", key, val_copy);
			/* Unsupprted type */
			rc = RC_DDNS_RSP_NOHOST;
		}
		if (val_copy)
			free(val_copy);
	} else {
		rc = RC_DDNS_RSP_NOHOST;
	}

	logit(LOG_DEBUG, "Key '%s' = %s", key, dest);

	return rc;
}

static const char* get_record_type(const char *address)
{
	if (strstr(address, ":"))
		return IPV6_RECORD_TYPE;

	return IPV4_RECORD_TYPE;
}

static int setup(ddns_t *ctx, ddns_info_t *info, ddns_alias_t *hostname)
{
	const char *record_type;
	struct dynudata *data;
	size_t len;
	const char *domain_name = info->creds.username;
	int rc = RC_OK;

	if (*domain_name == '\0' || !strchr(domain_name, '.'))
	{
		logit(LOG_ERR, "Invalid domain. Enter the intended domain in the username field.");
		return RC_DDNS_INVALID_OPTION;
	}

	data = calloc(1, sizeof(struct dynudata));
	if (!data)
		return RC_OUT_OF_MEMORY;

	if (info->data)
		free(info->data);
	info->data = data;

	record_type = get_record_type(hostname->address);
#if 0  // If I want to get the domain id, use this.  But I can get that id from the host request below.
	logit(LOG_DEBUG, "Domain: %s", domain_name);

	len = snprintf(ctx->request_buf, ctx->request_buflen,
		       DYNU_DOMAIN_ID_REQUEST,
			   domain_name,
		       info->user_agent,
		       info->creds.password);

	if (len >= ctx->request_buflen) {
		logit(LOG_ERR, "Request for domains did not fit into buffer.");
		return RC_BUFFER_OVERFLOW;
	}

	rc = json_extract(data->domain_id, MAX_ID, info, ctx->request_buf, len, "id");
	if (rc != RC_OK) {
		logit(LOG_ERR, "Domain '%s' not found.", domain_name);
		return rc;
	}
	#endif
	/* Query the unique dynu id from hostname.
		If more than one record is returned (round-robin dns?) use only the first and ignore the others. */
	len = snprintf(ctx->request_buf, ctx->request_buflen,
			DYNU_HOSTNAME_ID_REQUEST_BY_NAME,
			hostname->name,
			record_type,
			info->user_agent,
			info->creds.password);
	if (len >= ctx->request_buflen) {
		logit(LOG_ERR, "Request for hostname '%s' in domain id %s did not fit into buffer.",
			hostname->name, data->domain_id);
		return RC_BUFFER_OVERFLOW;
	}

	CHECK(retrieve_json(ctx->work_buf, ctx->work_buflen, info, ctx->request_buf, ctx->request_buflen));

	rc = json_extract(data->hostname_id, MAX_ID, ctx->work_buf, "id");
	if (rc == RC_DDNS_RSP_NOHOST) {
		strcpy(data->hostname_id, "");
		// Make a call to retrieve the domain_id
		return RC_OK;
	} else if (rc != RC_OK) {
		logit(LOG_INFO, "Hostname '%s' not found.", hostname->name);
		goto cleanup;
	}

	rc = json_extract(data->domain_id, MAX_ID, ctx->work_buf, "domainId");
	if (rc == RC_DDNS_RSP_NOHOST) {
		strcpy(data->domain_id, "");
		return RC_OK;
	} else if (rc != RC_OK) {
		logit(LOG_INFO, "DomainId for hostname '%s', id %s, not found.", hostname->name, data->hostname_id);
		goto cleanup;
	}
	rc = json_extract(data->nodename, MAXHOSTNAMELEN, ctx->work_buf, "nodeName");
	if (rc == RC_DDNS_RSP_NOHOST) {
		strcpy(data->nodename, "");
		return RC_OK;
	} else if (rc != RC_OK) {
		logit(LOG_INFO, "Nodename for hostname '%s', id %s, not found.", hostname->name, data->hostname_id);
		goto cleanup;
	}

	logit(LOG_DEBUG, "Dynu Host: '%s' (nodename '%s') Id: %s, Domain Id: %s", hostname->name, data->nodename, data->hostname_id, data->domain_id);

cleanup:
	/* Should I free the info->data I allocated?  I think not... */

	return rc;
}

static int request(ddns_t *ctx, ddns_info_t *info, ddns_alias_t *hostname)
{
	const char *record_type, *record_key;
	struct dynudata *data = (struct dynudata *)info->data;
	size_t content_len;
	char json_data[256];

	if (!*data->domain_id) {
		logit(LOG_ERR, "Cannot place request with a null domain_id");
		return -1;
	}

	record_type = get_record_type(hostname->address);
	if (strcmp(record_type, IPV4_RECORD_TYPE) == 0) {
		record_key = "ipv4Address";
	} else if (strcmp(record_type, IPV6_RECORD_TYPE) == 0) {
		record_key = "ipv6Address";
	}

	/* I need the node name, within the domain, not the whole hostname.
       For existing hosts, I got it back in setup().  If not, then
	   remove the domain if the specified name was qualified. */
	char *nodename = data->nodename;
	if (strlen(nodename) == 0) {
		char *domain_part = strstr(hostname->name, info->creds.username);
		if (domain_part == NULL) {
			nodename = hostname->name;
		} else {
			nodename = strndup(hostname->name, (domain_part - hostname->name - 1));
			/* I'm not checking for the dot, I'm assuming.  That's safe here, right?  */
			/* XXX LEAK! */
		}
	}

	if (info->ttl >= 0) {
		content_len = snprintf(json_data, sizeof(json_data),
					DYNU_UPDATE_JSON_FORMAT,
					nodename,
					record_type,
					record_key,
					hostname->address,
					info->ttl);
	} else {
		content_len = snprintf(json_data, sizeof(json_data),
					DYNU_UPDATE_JSON_FORMAT_NOTTL,
					nodename,
					record_type,
					record_key,
					hostname->address);
	}

	logit(LOG_DEBUG, "hostname_id is '%s', domain_id is '%s'",data->hostname_id, data->domain_id);
	if (strlen(data->hostname_id) == 0)
		return snprintf(ctx->request_buf, ctx->request_buflen,
			DYNU_HOSTNAME_CREATE_REQUEST,
			data->domain_id,
			info->user_agent,
			info->creds.password,
			content_len, json_data);

	return snprintf(ctx->request_buf, ctx->request_buflen,
			info->system->server_req,
			data->domain_id,
			data->hostname_id,
			info->user_agent,
			info->creds.password,
			content_len, json_data);
}

static int response(http_trans_t *trans, ddns_info_t *info, ddns_alias_t *hostname)
{
	int rc;

	(void)info;
	(void)hostname;

	rc = check_response_code(trans->status);
	if (rc == RC_OK && check_success_only(trans->rsp_body) < 0)
		rc = RC_DDNS_RSP_NOTOK;

	return rc;
}

PLUGIN_INIT(plugin_init)
{
	plugin_register(&plugin, DYNU_HOSTNAME_UPDATE_REQUEST);
	plugin_register_v6(&plugin, DYNU_HOSTNAME_UPDATE_REQUEST);
}

PLUGIN_EXIT(plugin_exit)
{
	plugin_unregister(&plugin);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
