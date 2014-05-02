/* t-http.c
 * Copyright (C) 1999, 2001, 2002, 2003, 2004, 2006, 2009, 2010,
 *               2011 Free Software Foundation, Inc.
 * Copyright (C) 2014 Werner Koch
 *
 * This file is part of GnuPG.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of either
 *
 *   - the GNU Lesser General Public License as published by the Free
 *     Software Foundation; either version 3 of the License, or (at
 *     your option) any later version.
 *
 * or
 *
 *   - the GNU General Public License as published by the Free
 *     Software Foundation; either version 2 of the License, or (at
 *     your option) any later version.
 *
 * or both in parallel, as here.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"
#include "logging.h"
#include "http.h"


#ifdef HTTP_USE_GNUTLS
# include <gnutls/gnutls.h>  /* For init, logging, and deinit.  */
#endif /*HTTP_USE_GNUTLS*/

#define PGM "t-http"

static int verbose;
static int debug;
static int no_verify;

/* static void */
/* read_dh_params (const char *fname) */
/* { */
/*   gpg_error_t err; */
/*   int rc; */
/*   FILE *fp; */
/*   struct stat st; */
/*   char *buf; */
/*   size_t buflen; */
/*   gnutls_datum_t datum; */

/*   fp = fopen (fname, "rb"); */
/*   if (!fp) */
/*     { */
/*       err = gpg_error_from_syserror (); */
/*       log_fatal ("can't open '%s': %s\n", fname, gpg_strerror (err)); */
/*     } */

/*   if (fstat (fileno(fp), &st)) */
/*     { */
/*       err = gpg_error_from_syserror (); */
/*       log_fatal ("can't stat '%s': %s\n", fname, gpg_strerror (err)); */
/*     } */

/*   buflen = st.st_size; */
/*   buf = xmalloc (buflen+1); */
/*   if (fread (buf, buflen, 1, fp) != 1) */
/*     { */
/*       err = gpg_error_from_syserror (); */
/*       log_fatal ("error reading '%s': %s\n", fname, gpg_strerror (err)); */
/*     } */
/*   fclose (fp); */

/*   datum.size = buflen; */
/*   datum.data = buf; */

/*   rc = gnutls_dh_params_import_pkcs3 (dh_params, &datum, GNUTLS_X509_FMT_PEM); */
/*   if (rc < 0) */
/*     log_fatal ("gnutls_dh_param_import failed: %s\n", gnutls_strerror (rc)); */

/*   xfree (buf); */
/* } */



static gpg_error_t
verify_callback (http_t hd, http_session_t session, int reserved)
{
  (void)hd;
  (void)reserved;
  return no_verify? 0 : http_verify_server_credentials (session);
}


static void
my_gnutls_log (int level, const char *text)
{
  fprintf (stderr, "gnutls:L%d: %s", level, text);
}


/* Prepend FNAME with the srcdir environment variable's value and
   return an allocated filename. */
static char *
prepend_srcdir (const char *fname)
{
  static const char *srcdir;
  char *result;

  if (!srcdir && !(srcdir = getenv ("srcdir")))
    srcdir = ".";

  result = xmalloc (strlen (srcdir) + 1 + strlen (fname) + 1);
  strcpy (result, srcdir);
  strcat (result, "/");
  strcat (result, fname);
  return result;
}


int
main (int argc, char **argv)
{
  int last_argc = -1;
  gpg_error_t err;
  int rc;
  parsed_uri_t uri;
  uri_tuple_t r;
  http_t hd;
  int c;
  unsigned int my_http_flags = 0;
  int no_out = 0;
  const char *cafile = NULL;
  http_session_t session = NULL;

  es_init ();
  log_set_prefix (PGM, 1 | 4);
  if (argc)
    { argc--; argv++; }
  while (argc && last_argc != argc )
    {
      last_argc = argc;
      if (!strcmp (*argv, "--"))
        {
          argc--; argv++;
          break;
        }
      else if (!strcmp (*argv, "--help"))
        {
          fputs ("usage: " PGM " URL\n"
                 "Options:\n"
                 "  --verbose       print timings etc.\n"
                 "  --debug         flyswatter\n"
                 "  --cacert FNAME  expect CA certificate in file FNAME\n"
                 "  --no-verify     do not verify the certificate\n"
                 "  --force-tls     use HTTP_FLAG_FORCE_TLS\n"
                 "  --no-out        do not print the content\n",
                 stdout);
          exit (0);
        }
      else if (!strcmp (*argv, "--verbose"))
        {
          verbose++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--debug"))
        {
          verbose += 2;
          debug++;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--cacert"))
        {
          argc--; argv++;
          if (argc)
            {
              cafile = *argv;
              argc--; argv++;
            }
        }
      else if (!strcmp (*argv, "--no-verify"))
        {
          no_verify = 1;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--force-tls"))
        {
          my_http_flags |= HTTP_FLAG_FORCE_TLS;
          argc--; argv++;
        }
      else if (!strcmp (*argv, "--no-out"))
        {
          no_out = 1;
          argc--; argv++;
        }
      else if (!strncmp (*argv, "--", 2))
        {
          fprintf (stderr, PGM ": unknown option '%s'\n", *argv);
          exit (1);
        }
    }
  if (argc != 1)
    {
      fprintf (stderr, PGM ": no or roo many URLS given\n");
      exit (1);
    }

  if (!cafile)
    cafile = prepend_srcdir ("tls-ca.pem");

#ifdef HTTP_USE_GNUTLS
  rc = gnutls_global_init ();
  if (rc)
    log_error ("gnutls_global_init failed: %s\n", gnutls_strerror (rc));

  http_register_tls_callback (verify_callback);
  http_register_tls_ca (cafile);

  err = http_session_new (&session, NULL);
  if (err)
    log_error ("http_session_new failed: %s\n", gpg_strerror (err));

  /* rc = gnutls_dh_params_init(&dh_params); */
  /* if (rc) */
  /*   log_error ("gnutls_dh_params_init failed: %s\n", gnutls_strerror (rc)); */
  /* read_dh_params ("dh_param.pem"); */

  /* rc = gnutls_certificate_set_x509_trust_file */
  /*   (certcred, "ca.pem", GNUTLS_X509_FMT_PEM); */
  /* if (rc) */
  /*   log_error ("gnutls_certificate_set_x509_trust_file failed: %s\n", */
  /*              gnutls_strerror (rc)); */

  /* gnutls_certificate_set_dh_params (certcred, dh_params); */

  gnutls_global_set_log_function (my_gnutls_log);
  /* gnutls_global_set_log_level (2); */

#endif /*HTTP_USE_GNUTLS*/

  rc = http_parse_uri (&uri, *argv, 1);
  if (rc)
    {
      log_error ("'%s': %s\n", *argv, gpg_strerror (rc));
      return 1;
    }

  printf ("Scheme: %s\n", uri->scheme);
  if (uri->opaque)
    printf ("Value : %s\n", uri->path);
  else
    {
      printf ("Auth  : %s\n", uri->auth? uri->auth:"[none]");
      printf ("Host  : %s\n", uri->host);
      printf ("Port  : %u\n", uri->port);
      printf ("Path  : %s\n", uri->path);
      for (r = uri->params; r; r = r->next)
        {
          printf ("Params: %s", r->name);
          if (!r->no_value)
            {
              printf ("=%s", r->value);
              if (strlen (r->value) != r->valuelen)
                printf (" [real length=%d]", (int) r->valuelen);
            }
          putchar ('\n');
        }
      for (r = uri->query; r; r = r->next)
        {
          printf ("Query : %s", r->name);
          if (!r->no_value)
            {
              printf ("=%s", r->value);
              if (strlen (r->value) != r->valuelen)
                printf (" [real length=%d]", (int) r->valuelen);
            }
          putchar ('\n');
        }
      printf ("TLS   : %s\n",
              uri->use_tls? "yes":
              (my_http_flags&HTTP_FLAG_FORCE_TLS)? "forced" : "no");

    }
  fflush (stdout);
  http_release_parsed_uri (uri);
  uri = NULL;

  rc = http_open_document (&hd, *argv, NULL, my_http_flags,
                           NULL, session, NULL, NULL);
  if (rc)
    {
      log_error ("can't get '%s': %s\n", *argv, gpg_strerror (rc));
      return 1;
    }
  log_info ("open_http_document succeeded; status=%u\n",
            http_get_status_code (hd));

  {
    const char **names;
    int i;

    names = http_get_header_names (hd);
    if (!names)
      log_fatal ("http_get_header_names failed: %s\n",
                 gpg_strerror (gpg_error_from_syserror ()));
    for (i = 0; names[i]; i++)
      printf ("HDR: %s: %s\n", names[i], http_get_header (hd, names[i]));
    xfree (names);
  }
  fflush (stdout);

  switch (http_get_status_code (hd))
    {
    case 200:
    case 400:
    case 401:
    case 403:
    case 404:
      {
        unsigned long count = 0;
        while ((c = es_getc (http_get_read_ptr (hd))) != EOF)
          {
            count++;
            if (!no_out)
              putchar (c);
          }
        log_info ("Received bytes: %lu\n", count);
      }
      break;
    case 301:
    case 302:
    case 307:
      log_info ("Redirected to: %s\n", http_get_header (hd, "Location"));
      break;
    }
  http_close (hd, 0);

  http_session_release (session);
#ifdef HTTP_USE_GNUTLS
  gnutls_global_deinit ();
#endif /*HTTP_USE_GNUTLS*/

  return 0;
}
