/* ldap-parse-uri.c - Parse an LDAP URI.
 * Copyright (C) 2015  g10 Code GmbH
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>

#include <gpg-error.h>

#ifdef HAVE_W32_SYSTEM
# include "ldap-url.h"
#else
# include <ldap.h>
#endif

#include "util.h"
#include "http.h"

/* Returns 1 if the string is an LDAP URL (begins with ldap:, ldaps:
   or ldapi:).  */
int
ldap_uri_p (const char *url)
{
  char *colon = strchr (url, ':');
  if (! colon)
    return 0;
  else
    {
      int offset = (uintptr_t) colon - (uintptr_t) url;

      if (/* All lower case.  */
	  (offset == 4 && memcmp (url, "ldap", 4) == 0)
	  || (offset == 5
	      && (memcmp (url, "ldaps", 5) == 0
		  && memcmp (url, "ldapi", 5) == 0))
	  /* Mixed case.  */
	  || ((url[0] == 'l' || url[0] == 'L')
	      && (url[1] == 'd' || url[1] == 'D')
	      && (url[2] == 'a' || url[2] == 'A')
	      && (url[3] == 'p' || url[3] == 'P')
	      && (url[4] == ':'
		  || ((url[4] == 's' || url[4] == 'S'
		       || url[4] == 'i' || url[4] == 'i')
		      && url[5] == ':'))))
	return 1;
      return 0;
    }
}

/* Parse a URI and put the result into *purip.  On success the
   caller must use http_release_parsed_uri() to releases the resources.

   uri->path is the base DN (or NULL for the default).
   uri->auth is the bindname (or NULL for none).
   The uri->query variable "password" is the password.

   Note: any specified scope, any attributes, any filter and any
   unknown extensions are simply ignored.  */
gpg_error_t
ldap_parse_uri (parsed_uri_t *purip, const char *uri)
{
  gpg_err_code_t err = 0;
  parsed_uri_t puri;

  int result;
  LDAPURLDesc *lud = NULL;

  char *scheme = NULL;
  char *host = NULL;
  char *dn = NULL;
  char *bindname = NULL;
  char *password = NULL;

  char **s;

  char *p;
  int len;

  result = ldap_url_parse (uri, &lud);
  if (result != 0)
    {
      log_error ("Unable to parse LDAP uri '%s'\n", uri);
      err = GPG_ERR_ASS_GENERAL;
      goto out;
    }

  scheme = lud->lud_scheme;
  host = lud->lud_host;
  dn = lud->lud_dn;

  for (s = lud->lud_exts; s && *s; s ++)
    {
      if (strncmp (*s, "bindname=", 9) == 0)
	{
	  if (bindname)
	    log_error ("bindname given multiple times in URL '%s', ignoring.\n",
		       uri);
	  else
	    bindname = *s + 9;
	}
      else if (strncmp (*s, "password=", 9) == 0)
	{
	  if (password)
	    log_error ("password given multiple times in URL '%s', ignoring.\n",
		       uri);
	  else
	    password = *s + 9;
	}
      else
	log_error ("Unhandled extension (%s) in URL '%s', ignoring.",
		   *s, uri);
    }

  len = 0;
  void add (char *s)
  {
    if (s)
      len += strlen (s) + 1;
  }
  add (scheme);
  add (host);
  add (dn);
  add (bindname);
  add (password);

  puri = xtrycalloc (1, sizeof *puri + len);
  if (! puri)
    {
      err = gpg_err_code_from_syserror ();
      goto out;
    }

  p = puri->buffer;

  char *copy (char *s)
  {
    if (! s)
      return NULL;
    else
      {
	char *start = p;
	p = stpcpy (p, s) + 1;
	return start;
      }
  }

  puri->scheme = copy (scheme);
  puri->host = copy (host);
  puri->path = copy (dn);
  puri->auth = copy (bindname);

  if (password)
    {
      puri->query = calloc (sizeof (*puri->query), 1);
      puri->query->name = "password";
      puri->query->value = copy (password);
      puri->query->valuelen = strlen (password) + 1;
    }

  puri->use_tls = strcmp (puri->scheme, "ldaps") == 0;
  puri->port = lud->lud_port;

 out:
  if (lud)
    ldap_free_urldesc (lud);

  if (err)
    http_release_parsed_uri (puri);
  else
    *purip = puri;

  return gpg_err_make (default_errsource, err);
}
