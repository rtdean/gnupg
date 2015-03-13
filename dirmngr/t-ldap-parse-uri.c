/* t-ldap-parse-uri.c - Regression tests for ldap-parse-uri.c.
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

#include "ldap-parse-uri.h"

#include "t-support.h"

static void
test_ldap_uri_p (void)
{
  struct test
  {
    const char *uri;
    int result;
  };

  struct test tests[] = {
    { "ldap://foo", 1 },
    { "ldap://", 1 },
    { "ldap:", 1 },
    { "ldap", 0 },
    { "ldapfoobar", 0 },

    { "ldaps://foo", 1 },
    { "ldaps://", 1 },
    { "ldaps:", 1 },
    { "ldaps", 0 },
    { "ldapsfoobar", 0 },

    { "ldapi://foo", 1 },
    { "ldapi://", 1 },
    { "ldapi:", 1 },
    { "ldapi", 0 },
    { "ldapifoobar", 0 },

    { "LDAP://FOO", 1 },
    { "LDAP://", 1 },
    { "LDAP:", 1 },
    { "LDAP", 0 },
    { "LDAPFOOBAR", 0 }
  };

  int test_count;

  void check (struct test *test)
  {
    int result = ldap_uri_p (test->uri);
    if (result != test->result)
      {
	printf ("'%s' is %san LDAP schema, but ldap_uri_p says opposite.\n",
		test->uri, test->result ? "" : "not ");
	fail(1000 * test_count);
      }
  }

  for (test_count = 1;
       test_count <= sizeof (tests) / sizeof (tests[0]);
       test_count ++)
    check (&tests[test_count - 1]);
}

static void
test_ldap_parse_uri (void)
{
  struct test
  {
    const char *uri;
    const char *scheme;
    const char *host;
    const int port;
    const int use_tls;
    const char *path;  /* basedn. */
    const char *auth;  /* binddn.  */
    const char *password;  /* query[1].  */
  };

  struct test tests[] = {
    { "ldap://", "ldap", NULL, 389, 0, NULL, NULL, NULL },
    { "ldap://host", "ldap", "host", 389, 0, NULL, NULL, NULL },
    { "ldap://host:100", "ldap", "host", 100, 0, NULL, NULL, NULL },
    { "ldaps://host", "ldaps", "host", 636, 1, NULL, NULL, NULL },
    { "ldap://host/ou%3DPGP%20Keys%2Cdc%3DEXAMPLE%2Cdc%3DORG",
      "ldap", "host", 389, 0, "ou=PGP Keys,dc=EXAMPLE,dc=ORG" },
    { "ldap://host/????bindname=uid%3Duser%2Cou%3DPGP%20Users%2Cdc%3DEXAMPLE%2Cdc%3DORG,password=foobar",
      "ldap", "host", 389, 0, "",
      "uid=user,ou=PGP Users,dc=EXAMPLE,dc=ORG", "foobar" }
  };

  int test_count;

  void check (struct test *test)
  {
    gpg_error_t err;
    parsed_uri_t puri;

    err = ldap_parse_uri (&puri, test->uri);
    if (err)
      {
	printf ("Parsing '%s' failed (%d).\n", test->uri, err);
	fail (test_count * 1000 + 0);
      }

    int cmp (const char *a, const char *b)
    {
      if (! a)
	a = "";
      if (! b)
	b = "";

      return strcmp (a, b) == 0;
    }

    if (! cmp(test->scheme, puri->scheme))
      {
	printf ("scheme mismatch: got '%s', expected '%s'.\n",
		puri->scheme, test->scheme);
	fail (test_count * 1000 + 1);
      }

    if (! cmp(test->host, puri->host))
      {
	printf ("host mismatch: got '%s', expected '%s'.\n",
		puri->host, test->host);
	fail (test_count * 1000 + 2);
      }

    if (test->port != puri->port)
      {
	printf ("port mismatch: got '%d', expected '%d'.\n",
		puri->port, test->port);
	fail (test_count * 1000 + 3);
      }

    if (test->use_tls != puri->use_tls)
      {
	printf ("use_tls mismatch: got '%d', expected '%d'.\n",
		puri->use_tls, test->use_tls);
	fail (test_count * 1000 + 4);
      }

    if (! cmp(test->path, puri->path))
      {
	printf ("path mismatch: got '%s', expected '%s'.\n",
		puri->path, test->path);
	fail (test_count * 1000 + 5);
      }

    if (! cmp(test->auth, puri->auth))
      {
	printf ("auth mismatch: got '%s', expected '%s'.\n",
		puri->auth, test->auth);
	fail (test_count * 1000 + 6);
      }

    if (! test->password && ! puri->query)
      /* Ok.  */
      ;
    else if (test->password && ! puri->query)
      {
	printf ("password mismatch: got NULL, expected '%s'.\n",
		test->auth);
	fail (test_count * 1000 + 7);
      }
    else if (! test->password && puri->query)
      {
	printf ("password mismatch: got something, expected NULL.\n");
	fail (test_count * 1000 + 8);
      }
    else if (! (test->password && puri->query
		&& puri->query->name && puri->query->value
		&& strcmp (puri->query->name, "password") == 0
		&& cmp (puri->query->value, test->password)))
      {
	printf ("password mismatch: got '%s:%s', expected 'password:%s'.\n",
		puri->query->name, puri->query->value,
		test->password);
	fail (test_count * 1000 + 9);
      }

    http_release_parsed_uri (puri);
  }

  for (test_count = 1;
       test_count <= sizeof (tests) / sizeof (tests[0]);
       test_count ++)
    check (&tests[test_count - 1]);
}

int
main (int argc, char **argv)
{
  (void)argc;
  (void)argv;

  test_ldap_uri_p ();
  test_ldap_parse_uri ();

  return 0;
}
