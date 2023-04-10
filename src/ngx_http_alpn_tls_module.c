#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "test/production.h"

static ngx_int_t ngx_http_alpn_tls_add_variables(ngx_conf_t *cf);
/* Restricting challenge data to stream module
static ngx_int_t ngx_http_alpn_tls_challenge_cert_variable(ngx_http_request_t *r,
  ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_alpn_tls_challenge_key_variable(ngx_http_request_t *r,
  ngx_http_variable_value_t *v, uintptr_t data);
*/
static ngx_int_t ngx_http_alpn_tls_production_cert_variable(ngx_http_request_t *r,
  ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_alpn_tls_production_key_variable(ngx_http_request_t *r,
  ngx_http_variable_value_t *v, uintptr_t data);

static ngx_http_module_t ngx_http_alpn_tls_module_ctx = {
  ngx_http_alpn_tls_add_variables,  /* preconfiguration */
  NULL,                             /* postconfiguration */
  NULL,                             /* create main configuration */
  NULL,                             /* merge main configuration */
  NULL,                             /* create server configuration */
  NULL,                             /* merge server configuration */
  NULL,                             /* create location configuration */
  NULL,                             /* merge location configuration */
};

ngx_module_t ngx_http_alpn_tls_module = {
  NGX_MODULE_V1,
  &ngx_http_alpn_tls_module_ctx,    /* module context */
  NULL,                             /* module directives */
  NGX_HTTP_MODULE,                  /* module type */
  NULL,                             /* init master */
  NULL,                             /* init module */
  NULL,                             /* init process */ // create zone/shmem for worker sharing
  NULL,                             /* init thread */
  NULL,                             /* exit thread */
  NULL,                             /* exit process */
  NULL,                             /* exit master */
  NGX_MODULE_V1_PADDING
};

static ngx_http_variable_t ngx_http_alpn_tls_vars[] = {
  /*
   * TODO - should HTTP have access to challenge, thse are likely only
   * stream use
  { ngx_string("challenge_crt"), NULL,
    ngx_http_alpn_tls_challenge_cert_variable, 0, 0, 0 },
  { ngx_string("challenge_key"), NULL,
    ngx_http_alpn_tls_challenge_key_variable, 0, 0, 0 },
  */
  { ngx_string("production_crt"), NULL,
    ngx_http_alpn_tls_production_cert_variable, 0, 0, 0 },
  { ngx_string("production_key"), NULL,
    ngx_http_alpn_tls_production_key_variable, 0, 0, 0 },

  ngx_http_null_variable
};

static ngx_int_t ngx_http_alpn_tls_add_variables(ngx_conf_t *cf) {
  ngx_http_variable_t *var, *v;

  for (v = ngx_http_alpn_tls_vars; v->name.len; v++) {
    var = ngx_http_add_variable(cf, &v->name, v->flags);
    if (var == NULL) {
      ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
          "FAILED LOADING VARIABLE %s", v->name);
      return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
          "VARIABLE LOADED %s", v->name);
    var->get_handler = v->get_handler;
    var->data = v->data;
  }
 
  return NGX_OK;
}

/*
static ngx_int_t ngx_http_alpn_tls_challenge_cert_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
      "DYNAMIC CHALLENGE CERT %s", self_cert);
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
      "DYNAMIC CHALLENGE CERT LEN %ui", ngx_strlen(self_cert));
  v->len = ngx_strlen(self_cert);
  v->data = (u_char *)self_cert;

  return NGX_OK;
}

static ngx_int_t ngx_http_alpn_tls_challenge_key_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
      "DYNAMIC CHALLENGE KEY %s", self_key);
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, s->connection->log, 0,
      "DYNAMIC CHALLENGE KEY LEN %ui", ngx_strlen(self_key));
  v->len = ngx_strlen(self_key);
  v->data = (u_char *)self_key;

  return NGX_OK;
}
*/

static uint cert_index = 0;
static ngx_int_t ngx_http_alpn_tls_production_cert_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
      "HTTP PRODUCTION_CRT %s", fake_certs[cert_index][CERT_ELEM]);
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
      "HTTP PRODUCTION_CRT LEN %ui", ngx_strlen(fake_certs[cert_index][CERT_ELEM]));
  v->len = ngx_strlen(fake_certs[cert_index][CERT_ELEM]);
  v->data = (u_char *)fake_certs[cert_index][CERT_ELEM];

  cert_index = (cert_index + 1) % NUM_CERTS;

  return NGX_OK;
}

static uint key_index = 0;
static ngx_int_t ngx_http_alpn_tls_production_key_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;

  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
      "HTTP PRODUCTION_KEY %s", fake_certs[key_index][KEY_ELEM]);
  ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
      "HTTP PRODUCTION_KEY LEN %ui", ngx_strlen(fake_certs[key_index][KEY_ELEM]));
  v->len = ngx_strlen(fake_certs[key_index][KEY_ELEM]);
  v->data = (u_char *)fake_certs[key_index][KEY_ELEM];

  key_index = (key_index + 1) % NUM_CERTS;

  return NGX_OK;
}
