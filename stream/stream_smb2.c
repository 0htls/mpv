#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "smb2/smb2.h"
#include "smb2/libsmb2.h"

#include "stream.h"

struct smb_url {
  char *domain;
  char *user;
  char *password;
  char *server;
  char *share;
  char *path;
};

struct priv {
 struct smb2_context *ctx;
 struct smb2fh *fh;
 struct smb_url *url;
};

static char *substr(const char *s, size_t start, size_t end)
{
  size_t len  = end - start;
  if (len <= (size_t)0) {
    return NULL;
  }

  char *str = malloc((len + 1) * sizeof(char));
  
  for (size_t i = 0; i < len; i++) {
    str[i] = s[start + i];
  }
  str[len] = '\0';

  return str;
}

static void smb_url_free(struct smb_url *u)
{
    free(u->domain);
    free(u->user);
    free(u->password);
    free(u->server);
    free(u->share);
    free(u->path);
    free(u);
}

static struct smb_url *smb_url_parse(const char *url)
{
  size_t start_index = 6;
  size_t len = strlen(url);
  struct smb_url *u = calloc(1, sizeof(struct  smb_url));

  if (strncmp(url, "smb://", 6)) {
    return NULL;
  }

  if(len > 1024) {
    return NULL;
  }

  bool has_domain = true;
  bool has_user = true;
  bool has_password = true;
  bool has_server = true;
  bool has_share = true;

  for (size_t i = start_index; i < len; i++) {
    if (has_domain && url[i] == ';') {
      has_domain = false;
      u->domain = substr(url, start_index, i);
      start_index = i + 1;
    }

    if (has_user && url[i] == ':') {
      has_domain = false;
      has_user = false;
      u->user = substr(url, start_index, i);
      start_index = i + 1;
    }

    if(has_password && url[i] == '@') {
      if (has_user) {
        u->user = substr(url, start_index, i);
      } else {
        u->password = substr(url, start_index, i);
      }
      
      has_domain = false;
      has_user = false;
      has_password = false;
      start_index = i + 1;
    }

    if (url[i] == '/') {
      if (has_user)
        goto error;

      if (has_server) {
        has_server = false;
        u->server = substr(url, start_index, i);\
        start_index = i + 1;
      } else if (has_share) {
        has_share = false;
        u->share = substr(url, start_index, i);
        start_index = i + 1;
        break;
      }
    }
  }

  if (!has_share && start_index < len) {
    u->path = substr(url, start_index, len);
  }

  if (!u->user || !u->server || !u->share || !u->path) {
    goto error;
  }

  return u;

  error:
    smb_url_free(u);
    return NULL;
}

static int64_t get_size(stream_t *s)
{
  struct priv *p = s->priv;
  struct smb2_stat_64 stat;
  if (smb2_fstat(p->ctx, p->fh, &stat) == 0)
    return stat.smb2_size;
  return -1;
}

static int seek(stream_t *s, int64_t newpos) 
{
  struct priv *p = s->priv;
  return smb2_lseek(p->ctx, p->fh, newpos, SEEK_SET, NULL);
}

static int fill_buffer(stream_t *s, char* buffer, int max_len)
{
  struct priv *p = s->priv;
  return smb2_read(p->ctx, p->fh, buffer, max_len);
}

static int write_buffer(stream_t *s, char* buffer, int len) 
{
  struct priv *p = s->priv;
  return smb2_write(p->ctx, p->fh, buffer, len);
}

static void close_f(stream_t *s) 
{
  struct priv *p = s->priv;

  smb2_close(p->ctx, p->fh);
  smb_url_free(p->url);
  smb2_disconnect_share(p->ctx);
  smb2_destroy_context(p->ctx);
}

static int open_f (stream_t *stream) 
{
  struct smb2_context *ctx = NULL;
  struct smb_url *url = NULL;
  struct smb2_fh *fh = NULL;

  bool is_connected = false;

  struct priv *priv = talloc_zero(stream, struct priv);
  stream->priv = priv;

  ctx = smb2_init_context();
  if (!ctx) {
    MP_ERR(stream, "Could not init smb2_context\n");
    goto out;
  }
  priv->ctx = ctx;

  url = smb_url_parse(stream->url);
  if (!url) {
    MP_ERR(stream, "failed to parse url: %s\n", smb2_get_error(ctx));
    goto out;
  }
  priv->url = url;

  smb2_set_security_mode(ctx, SMB2_NEGOTIATE_SIGNING_ENABLED);

  smb2_set_user(ctx, url->user);
  if (url->domain) {
    smb2_set_domain(ctx, url->domain);
  }
  if (url->password) {
    smb2_set_password(ctx, url->password);
  }


  is_connected = smb2_connect_share(ctx, url->server, url->share, url->user) == 0;
  if (!is_connected) {
    MP_ERR(stream, "smb2_connect_share failed");
    goto out;
  }

  bool write = stream->mode == STREAM_WRITE;

  int flags = write ? O_RDWR | O_CREAT : O_RDONLY;
  fh = smb2_open(ctx, url->path, flags);
  if (!fh) {
    MP_ERR(stream, "smb2_open failed");
    goto out;
  }
  priv->fh = fh;

  int64_t len = smb2_lseek(ctx, fh, 0, SEEK_END, NULL);
  smb2_lseek(ctx, fh, 0, SEEK_SET, NULL);
  if (len != (int64_t)-1) {
    stream->seek = seek;
    stream->seekable = true;
  }

  stream->fill_buffer = fill_buffer;
  stream->write_buffer = write_buffer;
  stream->close = close_f;
  stream->get_size = get_size;
  stream->streaming = true;

  return STREAM_OK;

  out:
    talloc_free(priv);
    stream->priv = NULL;
    if (url)
      smb_url_free(url);
    if (is_connected)
      smb2_disconnect_share(ctx);
    if (ctx)
      smb2_destroy_context(ctx);
  
    return STREAM_ERROR;
}

const stream_info_t stream_info_smb2 = {
    .name = "smb",
    .open = open_f,
    .protocols = (const char*const[]){"smb", NULL},
    .can_write = true,
};