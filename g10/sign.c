/* sign.c - sign data
 * Copyright (C) 1998, 1999, 2000, 2001 Free Software Foundation, Inc.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h> /* need sleep() */

#include "options.h"
#include "packet.h"
#include "errors.h"
#include "iobuf.h"
#include "keydb.h"
#include "memory.h"
#include "util.h"
#include "main.h"
#include "filter.h"
#include "ttyio.h"
#include "trustdb.h"
#include "status.h"
#include "i18n.h"


#ifdef HAVE_DOSISH_SYSTEM
  #define LF "\r\n"
  void __stdcall Sleep(ulong);
  #define sleep(a)  Sleep((a)*1000)
#else
  #define LF "\n"
#endif


/****************
 * Create a notation.  It is assumed that the stings in STRLIST
 * are already checked to contain only printable data and have a valid
 * NAME=VALUE format.
 */
static void
mk_notation_and_policy( PKT_signature *sig )
{
    const char *string, *s;
    byte *buf;
    unsigned n1, n2;

    /* notation data */
    if( opt.notation_data && sig->version < 4 )
	log_info("can't put notation data into v3 signatures\n");
    else if( opt.notation_data ) {
	STRLIST nd = opt.notation_data;

	for( ; nd; nd = nd->next )  {
	    string = nd->d;
	    s = strchr( string, '=' );
	    if( !s )
		BUG(); /* we have already parsed this */
	    n1 = s - string;
	    s++;
	    n2 = strlen(s);
	    buf = m_alloc( 8 + n1 + n2 );
	    buf[0] = 0x80; /* human readable */
	    buf[1] = buf[2] = buf[3] = 0;
	    buf[4] = n1 >> 8;
	    buf[5] = n1;
	    buf[6] = n2 >> 8;
	    buf[7] = n2;
	    memcpy(buf+8, string, n1 );
	    memcpy(buf+8+n1, s, n2 );
	    build_sig_subpkt( sig, SIGSUBPKT_NOTATION
			      | ((nd->flags & 1)? SIGSUBPKT_FLAG_CRITICAL:0),
			      buf, 8+n1+n2 );
	}
    }

    /* set policy URL */
    if( (s=opt.set_policy_url) ) {
	if( *s == '!' )
	    build_sig_subpkt( sig, SIGSUBPKT_POLICY | SIGSUBPKT_FLAG_CRITICAL,
			      s+1, strlen(s+1) );
	else
	    build_sig_subpkt( sig, SIGSUBPKT_POLICY, s, strlen(s) );
    }
}


/*
 * Helper to hash a user ID packet.  
 */
static void
hash_uid (MD_HANDLE md, int sigversion, const PKT_user_id *uid)
{
    if ( sigversion >= 4 ) {
        byte buf[5];
        buf[0] = 0xb4;	          /* indicates a userid packet */
        buf[1] = uid->len >> 24;  /* always use 4 length bytes */
        buf[2] = uid->len >> 16;
        buf[3] = uid->len >>  8;
        buf[4] = uid->len;
        md_write( md, buf, 5 );
    }
    md_write (md, uid->name, uid->len );
}


/*
 * Helper to hash some parts from the signature
 */
static void
hash_sigversion_to_magic (MD_HANDLE md, const PKT_signature *sig)
{
    if (sig->version >= 4) 
        md_putc (md, sig->version);
    md_putc (md, sig->sig_class);
    if (sig->version < 4) {
        u32 a = sig->timestamp;
        md_putc (md, (a >> 24) & 0xff );
        md_putc (md, (a >> 16) & 0xff );
        md_putc (md, (a >>  8) & 0xff );
        md_putc (md,  a	       & 0xff );
    }
    else {
        byte buf[6];
        size_t n;
        
        md_putc (md, sig->pubkey_algo);
        md_putc (md, sig->digest_algo);
        if (sig->hashed) {
            n = sig->hashed->len;
            md_putc (md, (n >> 8) );
            md_putc (md,  n       );
            md_write (md, sig->hashed->data, n );
            n += 6;
        }
        else {
            md_putc (md, 0);  /* always hash the length of the subpacket*/
            md_putc (md, 0);
            n = 6;
        }
        /* add some magic */
        buf[0] = sig->version;
        buf[1] = 0xff;
        buf[2] = n >> 24; /* hmmm, n is only 16 bit, so this is always 0 */
        buf[3] = n >> 16;
        buf[4] = n >>  8;
        buf[5] = n;
        md_write (md, buf, 6);
    }
}


static int
do_sign( PKT_secret_key *sk, PKT_signature *sig,
	 MD_HANDLE md, int digest_algo )
{
    MPI frame;
    byte *dp;
    int rc;

    if( sk->timestamp > sig->timestamp ) {
	ulong d = sk->timestamp - sig->timestamp;
	log_info( d==1 ? _("key has been created %lu second "
			   "in future (time warp or clock problem)\n")
		       : _("key has been created %lu seconds "
			   "in future (time warp or clock problem)\n"), d );
	if( !opt.ignore_time_conflict )
	    return G10ERR_TIME_CONFLICT;
    }


    print_pubkey_algo_note(sk->pubkey_algo);

    if( !digest_algo )
	digest_algo = md_get_algo(md);

    print_digest_algo_note( digest_algo );
    dp = md_read( md, digest_algo );
    sig->digest_algo = digest_algo;
    sig->digest_start[0] = dp[0];
    sig->digest_start[1] = dp[1];
    frame = encode_md_value( sk->pubkey_algo, md,
			     digest_algo, mpi_get_nbits(sk->skey[0]), 0 );
    rc = pubkey_sign( sk->pubkey_algo, sig->data, frame, sk->skey );
    mpi_free(frame);
    if (!rc && !opt.no_sig_create_check) {
        /* check that the signature verification worked and nothing is
         * fooling us e.g. by a bug in the signature create
         * code or by deliberately introduced faults. */
        PKT_public_key *pk = m_alloc_clear (sizeof *pk);

        if( get_pubkey( pk, sig->keyid ) )
            rc = G10ERR_NO_PUBKEY;
        else {
            frame = encode_md_value (pk->pubkey_algo, md,
                                     sig->digest_algo,
                                     mpi_get_nbits(pk->pkey[0]), 0);
            rc = pubkey_verify (pk->pubkey_algo, frame, sig->data, pk->pkey,
                                NULL, NULL );
            mpi_free (frame);
        }
        if (rc)
            log_error (_("checking created signature failed: %s\n"),
                         g10_errstr (rc));
        free_public_key (pk);
    }
    if( rc )
	log_error(_("signing failed: %s\n"), g10_errstr(rc) );
    else {
	if( opt.verbose ) {
	    char *ustr = get_user_id_string( sig->keyid );
	    log_info(_("%s signature from: %s\n"),
		      pubkey_algo_to_string(sk->pubkey_algo), ustr );
	    m_free(ustr);
	}
    }
    return rc;
}



int
complete_sig( PKT_signature *sig, PKT_secret_key *sk, MD_HANDLE md )
{
    int rc=0;

    if( !(rc=check_secret_key( sk, 0 )) )
	rc = do_sign( sk, sig, md, 0 );
    return rc;
}

static int
hash_for(int pubkey_algo, int packet_version )
{
    if( opt.def_digest_algo )
	return opt.def_digest_algo;
    if( pubkey_algo == PUBKEY_ALGO_DSA )
	return DIGEST_ALGO_SHA1;
    if( pubkey_algo == PUBKEY_ALGO_RSA && packet_version < 4 )
	return DIGEST_ALGO_MD5;
    return DEFAULT_DIGEST_ALGO;
}

static int
only_old_style( SK_LIST sk_list )
{
    SK_LIST sk_rover = NULL;
    int old_style = 0;

    /* if there are only old style capable key we use the old sytle */
    for( sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
	PKT_secret_key *sk = sk_rover->sk;
	if( sk->pubkey_algo == PUBKEY_ALGO_RSA && sk->version < 4 )
	    old_style = 1;
	else
	    return 0;
    }
    return old_style;
}


static void
print_status_sig_created ( PKT_secret_key *sk, PKT_signature *sig, int what )
{
    byte array[MAX_FINGERPRINT_LEN], *p;
    char buf[100+MAX_FINGERPRINT_LEN*2];
    size_t i, n;

    sprintf(buf, "%c %d %d %02x %lu ",
	    what, sig->pubkey_algo, sig->digest_algo, sig->sig_class,
	    (ulong)sig->timestamp );

    fingerprint_from_sk( sk, array, &n );
    p = buf + strlen(buf);
    for(i=0; i < n ; i++ )
	sprintf(p+2*i, "%02X", array[i] );

    write_status_text( STATUS_SIG_CREATED, buf );
}


/*
 * Loop over the secret certificates in SK_LIST and build the one pass
 * signature packets.  OpenPGP says that the data should be bracket by
 * the onepass-sig and signature-packet; so we build these onepass
 * packet here in reverse order 
 */
static int
write_onepass_sig_packets (SK_LIST sk_list, IOBUF out, int sigclass )
{
    int skcount;
    SK_LIST sk_rover;

    for (skcount=0, sk_rover=sk_list; sk_rover; sk_rover = sk_rover->next)
        skcount++;

    for (; skcount; skcount--) {
        PKT_secret_key *sk;
        PKT_onepass_sig *ops;
        PACKET pkt;
        int i, rc;
        
        for (i=0, sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
            if (++i == skcount)
                break;
        }

        sk = sk_rover->sk;
        ops = m_alloc_clear (sizeof *ops);
        ops->sig_class = sigclass;
        ops->digest_algo = hash_for (sk->pubkey_algo, sk->version);
        ops->pubkey_algo = sk->pubkey_algo;
        keyid_from_sk (sk, ops->keyid);
        ops->last = (skcount == 1);
        
        init_packet(&pkt);
        pkt.pkttype = PKT_ONEPASS_SIG;
        pkt.pkt.onepass_sig = ops;
        rc = build_packet (out, &pkt);
        free_packet (&pkt);
        if (rc) {
            log_error ("build onepass_sig packet failed: %s\n",
                       g10_errstr(rc));
            return rc;
        }
    }

    return 0;
}

/*
 * Helper to write the plaintext (literal data) packet
 */
static int
write_plaintext_packet (IOBUF out, IOBUF inp, const char *fname, int ptmode)
{
    PKT_plaintext *pt = NULL;
    u32 filesize;
    int rc = 0;

    if (!opt.no_literal) {
        if (fname || opt.set_filename) {
            char *s = make_basename (opt.set_filename? opt.set_filename
                                                     : fname);
            pt = m_alloc (sizeof *pt + strlen(s) - 1);
            pt->namelen = strlen (s);
            memcpy (pt->name, s, pt->namelen);
            m_free (s);
        }
        else { /* no filename */
            pt = m_alloc (sizeof *pt - 1);
            pt->namelen = 0;
        }
    }

    /* try to calculate the length of the data */
    if (fname) {
        if( !(filesize = iobuf_get_filelength(inp)) )
            log_info (_("WARNING: `%s' is an empty file\n"), fname);

        /* we can't yet encode the length of very large files,
         * so we switch to partial length encoding in this case */
        if (filesize >= IOBUF_FILELENGTH_LIMIT)
            filesize = 0;

        /* because the text_filter modifies the length of the
         * data, it is not possible to know the used length
         * without a double read of the file - to avoid that
         * we simple use partial length packets.
         */
        if ( ptmode == 't' )
            filesize = 0;
    }
    else {
        filesize = opt.set_filesize? opt.set_filesize : 0; /* stdin */
    }

    if (!opt.no_literal) {
        PACKET pkt;

        pt->timestamp = make_timestamp ();
        pt->mode = ptmode;
        pt->len = filesize;
        pt->new_ctb = !pt->len && !opt.rfc1991;
        pt->buf = inp;
        init_packet(&pkt);
        pkt.pkttype = PKT_PLAINTEXT;
        pkt.pkt.plaintext = pt;
        /*cfx.datalen = filesize? calc_packet_length( &pkt ) : 0;*/
        if( (rc = build_packet (out, &pkt)) )
            log_error ("build_packet(PLAINTEXT) failed: %s\n",
                       g10_errstr(rc) );
        pt->buf = NULL;
    }
    else {
        byte copy_buffer[4096];
        int  bytes_copied;

        while ((bytes_copied = iobuf_read(inp, copy_buffer, 4096)) != -1)
            if (iobuf_write(out, copy_buffer, bytes_copied) == -1) {
                rc = G10ERR_WRITE_FILE;
                log_error ("copying input to output failed: %s\n",
                           g10_errstr(rc));
                break;
            }
        memset(copy_buffer, 0, 4096); /* burn buffer */
    }
    /* fixme: it seems that we never freed pt/pkt */
    
    return rc;
}

/*
 * Write the signatures from the SK_LIST to OUT. HASH must be a non-finalized
 * hash which will not be changes here.
 */
static int
write_signature_packets (SK_LIST sk_list, IOBUF out, MD_HANDLE hash,
                         int sigclass, int old_style, int status_letter)
{
    SK_LIST sk_rover;

    /* loop over the secret certificates */
    for (sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next) {
	PKT_secret_key *sk;
	PKT_signature *sig;
	MD_HANDLE md;
        int rc;

	sk = sk_rover->sk;

	/* build the signature packet */
	sig = m_alloc_clear (sizeof *sig);
	sig->version = (old_style || opt.force_v3_sigs)? 3 : sk->version;
	keyid_from_sk (sk, sig->keyid);
	sig->digest_algo = hash_for (sk->pubkey_algo, sk->version);
	sig->pubkey_algo = sk->pubkey_algo;
	sig->timestamp = make_timestamp();
	sig->sig_class = sigclass;

	md = md_copy (hash);

	if (sig->version >= 4)
	    build_sig_subpkt_from_sig (sig);
	mk_notation_and_policy (sig);

        hash_sigversion_to_magic (md, sig);
	md_final (md);

	rc = do_sign( sk, sig, md, hash_for (sig->pubkey_algo, sk->version) );
	md_close (md);

	if( !rc ) { /* and write it */
            PACKET pkt;

	    init_packet(&pkt);
	    pkt.pkttype = PKT_SIGNATURE;
	    pkt.pkt.signature = sig;
	    rc = build_packet (out, &pkt);
	    if (!rc && is_status_enabled()) {
		print_status_sig_created ( sk, sig, status_letter);
	    }
	    free_packet (&pkt);
	    if (rc)
		log_error ("build signature packet failed: %s\n",
                           g10_errstr(rc) );
	}
	if( rc )
	    return rc;;
    }

    return 0;
}

/****************
 * Sign the files whose names are in FILENAME.
 * If DETACHED has the value true,
 * make a detached signature.  If FILENAMES->d is NULL read from stdin
 * and ignore the detached mode.  Sign the file with all secret keys
 * which can be taken from LOCUSR, if this is NULL, use the default one
 * If ENCRYPTFLAG is true, use REMUSER (or ask if it is NULL) to encrypt the
 * signed data for these users.
 * If OUTFILE is not NULL; this file is used for output and the function
 * does not ask for overwrite permission; output is then always
 * uncompressed, non-armored and in binary mode.
 */
int
sign_file( STRLIST filenames, int detached, STRLIST locusr,
	   int encryptflag, STRLIST remusr, const char *outfile )
{
    const char *fname;
    armor_filter_context_t afx;
    compress_filter_context_t zfx;
    md_filter_context_t mfx;
    text_filter_context_t tfx;
    encrypt_filter_context_t efx;
    IOBUF inp = NULL, out = NULL;
    PACKET pkt;
    int rc = 0;
    PK_LIST pk_list = NULL;
    SK_LIST sk_list = NULL;
    SK_LIST sk_rover = NULL;
    int multifile = 0;
    int old_style = opt.rfc1991;
    int compr_algo = -1; /* unknown */


    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);
    memset( &mfx, 0, sizeof mfx);
    memset( &tfx, 0, sizeof tfx);
    memset( &efx, 0, sizeof efx);
    init_packet( &pkt );

    if( filenames ) {
	fname = filenames->d;
	multifile = !!filenames->next;
    }
    else
	fname = NULL;

    if( fname && filenames->next && (!detached || encryptflag) )
	log_bug("multiple files can only be detached signed");

    if( (rc=build_sk_list( locusr, &sk_list, 1, PUBKEY_USAGE_SIG )) )
	goto leave;
    if( !old_style )
	old_style = only_old_style( sk_list );

    if( encryptflag ) {
	if( (rc=build_pk_list( remusr, &pk_list, PUBKEY_USAGE_ENC )) )
	    goto leave;
	if( !old_style )
	    compr_algo = select_algo_from_prefs( pk_list, PREFTYPE_ZIP );
    }

    /* prepare iobufs */
    if( multifile )  /* have list of filenames */
	inp = NULL; /* we do it later */
    else if( !(inp = iobuf_open(fname)) ) {
	log_error("can't open %s: %s\n", fname? fname: "[stdin]",
					strerror(errno) );
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }

    if( outfile ) {
	if( !(out = iobuf_create( outfile )) ) {
	    log_error(_("can't create %s: %s\n"), outfile, strerror(errno) );
	    rc = G10ERR_CREATE_FILE;
	    goto leave;
	}
	else if( opt.verbose )
	    log_info(_("writing to `%s'\n"), outfile );
    }
    else if( (rc = open_outfile( fname, opt.armor? 1: detached? 2:0, &out )))
	goto leave;

    /* prepare to calculate the MD over the input */
    if( opt.textmode && !outfile )
	iobuf_push_filter( inp, text_filter, &tfx );
    mfx.md = md_open(0, 0);

    for( sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
	PKT_secret_key *sk = sk_rover->sk;
	md_enable(mfx.md, hash_for(sk->pubkey_algo, sk->version ));
    }

    if( !multifile )
	iobuf_push_filter( inp, md_filter, &mfx );

    if( detached && !encryptflag && !opt.rfc1991 )
	afx.what = 2;

    if( opt.armor && !outfile  )
	iobuf_push_filter( out, armor_filter, &afx );

    if( encryptflag ) {
	efx.pk_list = pk_list;
	/* fixme: set efx.cfx.datalen if known */
	iobuf_push_filter( out, encrypt_filter, &efx );
    }

    if( opt.compress && !outfile && ( !detached || opt.compress_sigs) ) {
	if( !compr_algo )
	    ; /* don't use compression */
	else {
	    if( old_style
		|| compr_algo == 1
		|| (compr_algo == -1 && !encryptflag) )
		zfx.algo = 1; /* use the non optional algorithm */
	    iobuf_push_filter( out, compress_filter, &zfx );
	}
    }

    /* Write the one-pass signature packets if needed */
    if (!detached && !old_style) {
        rc = write_onepass_sig_packets (sk_list, out,
                                        opt.textmode && !outfile ? 0x01:0x00);
        if (rc)
            goto leave;
    }

    /* setup the inner packet */
    if( detached ) {
	if( multifile ) {
	    STRLIST sl;

	    if( opt.verbose )
		log_info(_("signing:") );
	    /* must walk reverse trough this list */
	    for( sl = strlist_last(filenames); sl;
			sl = strlist_prev( filenames, sl ) ) {
		if( !(inp = iobuf_open(sl->d)) ) {
		    log_error(_("can't open %s: %s\n"),
					    sl->d, strerror(errno) );
		    rc = G10ERR_OPEN_FILE;
		    goto leave;
		}
		if( opt.verbose )
		    fprintf(stderr, " `%s'", sl->d );
		iobuf_push_filter( inp, md_filter, &mfx );
		while( iobuf_get(inp) != -1 )
		    ;
		iobuf_close(inp); inp = NULL;
	    }
	    if( opt.verbose )
		putc( '\n', stderr );
	}
	else {
	    /* read, so that the filter can calculate the digest */
	    while( iobuf_get(inp) != -1 )
		;
	}
    }
    else {
        rc = write_plaintext_packet (out, inp, fname,
                                     opt.textmode && !outfile ? 't':'b');
    }

    /* catch errors from above */
    if (rc)
	goto leave;

    /* write the signatures */
    rc = write_signature_packets (sk_list, out, mfx.md,
                                  opt.textmode && !outfile? 0x01 : 0x00,
                                  old_style, detached ? 'D':'S');
    if( rc )
        goto leave;


  leave:
    if( rc )
	iobuf_cancel(out);
    else {
	iobuf_close(out);
        if (encryptflag)
            write_status( STATUS_END_ENCRYPTION );
    }
    iobuf_close(inp);
    md_close( mfx.md );
    release_sk_list( sk_list );
    release_pk_list( pk_list );
    return rc;
}



/****************
 * make a clear signature. note that opt.armor is not needed
 */
int
clearsign_file( const char *fname, STRLIST locusr, const char *outfile )
{
    armor_filter_context_t afx;
    MD_HANDLE textmd = NULL;
    IOBUF inp = NULL, out = NULL;
    PACKET pkt;
    int rc = 0;
    SK_LIST sk_list = NULL;
    SK_LIST sk_rover = NULL;
    int old_style = opt.rfc1991;
    int only_md5 = 0;

    memset( &afx, 0, sizeof afx);
    init_packet( &pkt );

    if( (rc=build_sk_list( locusr, &sk_list, 1, PUBKEY_USAGE_SIG )) )
	goto leave;
    if( !old_style )
	old_style = only_old_style( sk_list );

    /* prepare iobufs */
    if( !(inp = iobuf_open(fname)) ) {
	log_error("can't open %s: %s\n", fname? fname: "[stdin]",
					strerror(errno) );
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }

    if( outfile ) {
	if( !(out = iobuf_create( outfile )) ) {
	    log_error(_("can't create %s: %s\n"), outfile, strerror(errno) );
	    rc = G10ERR_CREATE_FILE;
	    goto leave;
	}
	else if( opt.verbose )
	    log_info(_("writing to `%s'\n"), outfile );
    }
    else if( (rc = open_outfile( fname, 1, &out )) )
	goto leave;

    iobuf_writestr(out, "-----BEGIN PGP SIGNED MESSAGE-----" LF );

    for( sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
	PKT_secret_key *sk = sk_rover->sk;
	if( hash_for(sk->pubkey_algo, sk->version) == DIGEST_ALGO_MD5 )
	    only_md5 = 1;
	else {
	    only_md5 = 0;
	    break;
	}
    }

    if( old_style && only_md5 )
	iobuf_writestr(out, LF );
    else {
	const char *s;
	int any = 0;
	byte hashs_seen[256];

	memset( hashs_seen, 0, sizeof hashs_seen );
	iobuf_writestr(out, "Hash: " );
	for( sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
	    PKT_secret_key *sk = sk_rover->sk;
	    int i = hash_for(sk->pubkey_algo, sk->version);

	    if( !hashs_seen[ i & 0xff ] ) {
		s = digest_algo_to_string( i );
		if( s ) {
		    hashs_seen[ i & 0xff ] = 1;
		    if( any )
			iobuf_put(out, ',' );
		    iobuf_writestr(out, s );
		    any = 1;
		}
	    }
	}
	assert(any);
	iobuf_writestr(out, LF );
	if( opt.not_dash_escaped )
	    iobuf_writestr( out,
		"NotDashEscaped: You need GnuPG to verify this message" LF );
	iobuf_writestr(out, LF );
    }


    textmd = md_open(0, 0);
    for( sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next ) {
	PKT_secret_key *sk = sk_rover->sk;
	md_enable(textmd, hash_for(sk->pubkey_algo, sk->version));
    }
    if ( DBG_HASHING )
	md_start_debug( textmd, "clearsign" );
    copy_clearsig_text( out, inp, textmd,
			!opt.not_dash_escaped, opt.escape_from, old_style );
    /* fixme: check for read errors */

    /* now write the armor */
    afx.what = 2;
    iobuf_push_filter( out, armor_filter, &afx );

    /* write the signatures */
    rc = write_signature_packets (sk_list, out, textmd,
                                  0x01, old_style, 'C');
    if( rc )
        goto leave;

  leave:
    if( rc )
	iobuf_cancel(out);
    else
	iobuf_close(out);
    iobuf_close(inp);
    md_close( textmd );
    release_sk_list( sk_list );
    return rc;
}

/*
 * Sign and conventionally encrypt the given file.
 * FIXME: Far too much code is duplicated - revamp the whole file.
 */
int
sign_symencrypt_file (const char *fname, STRLIST locusr)
{
    armor_filter_context_t afx;
    compress_filter_context_t zfx;
    md_filter_context_t mfx;
    text_filter_context_t tfx;
    cipher_filter_context_t cfx;
    IOBUF inp = NULL, out = NULL;
    PACKET pkt;
    STRING2KEY *s2k = NULL;
    int rc = 0;
    SK_LIST sk_list = NULL;
    SK_LIST sk_rover = NULL;
    int old_style = opt.rfc1991;
    int compr_algo = -1; /* unknown */
    int algo;

    memset( &afx, 0, sizeof afx);
    memset( &zfx, 0, sizeof zfx);
    memset( &mfx, 0, sizeof mfx);
    memset( &tfx, 0, sizeof tfx);
    memset( &cfx, 0, sizeof cfx);
    init_packet( &pkt );

    rc = build_sk_list (locusr, &sk_list, 1, PUBKEY_USAGE_SIG);
    if (rc) 
	goto leave;
    if( !old_style )
	old_style = only_old_style( sk_list );

    /* prepare iobufs */
    inp = iobuf_open(fname);
    if( !inp ) {
	log_error("can't open %s: %s\n", fname? fname: "[stdin]",
					strerror(errno) );
	rc = G10ERR_OPEN_FILE;
	goto leave;
    }

    /* prepare key */
    s2k = m_alloc_clear( sizeof *s2k );
    s2k->mode = opt.rfc1991? 0:opt.s2k_mode;
    s2k->hash_algo = opt.def_digest_algo ? opt.def_digest_algo
	                                 : opt.s2k_digest_algo;

    algo = opt.def_cipher_algo ? opt.def_cipher_algo : opt.s2k_cipher_algo;
    if (!opt.quiet || !opt.batch)
        log_info (_("%s encryption will be used\n"),
		    cipher_algo_to_string(algo) );
    cfx.dek = passphrase_to_dek( NULL, 0, algo, s2k, 2 );

    if (!cfx.dek || !cfx.dek->keylen) {
        rc = G10ERR_PASSPHRASE;
        log_error(_("error creating passphrase: %s\n"), g10_errstr(rc) );
        goto leave;
    }

    /* now create the outfile */
    rc = open_outfile (fname, opt.armor? 1:0, &out);
    if (rc)
	goto leave;

    /* prepare to calculate the MD over the input */
    if (opt.textmode)
	iobuf_push_filter (inp, text_filter, &tfx);
    mfx.md = md_open(0, 0);

    for (sk_rover = sk_list; sk_rover; sk_rover = sk_rover->next) {
	PKT_secret_key *sk = sk_rover->sk;
	md_enable (mfx.md, hash_for (sk->pubkey_algo, sk->version ));
    }

    iobuf_push_filter (inp, md_filter, &mfx);

    /* Push armor output filter */
    if (opt.armor)
	iobuf_push_filter (out, armor_filter, &afx);

    /* Write the symmetric key packet */
    /*(current filters: armor)*/
    if (!opt.rfc1991) {
	PKT_symkey_enc *enc = m_alloc_clear( sizeof *enc );
	enc->version = 4;
	enc->cipher_algo = cfx.dek->algo;
	enc->s2k = *s2k;
	pkt.pkttype = PKT_SYMKEY_ENC;
	pkt.pkt.symkey_enc = enc;
	if( (rc = build_packet( out, &pkt )) )
	    log_error("build symkey packet failed: %s\n", g10_errstr(rc) );
	m_free(enc);
    }

    /* Push the encryption filter */
    iobuf_push_filter( out, cipher_filter, &cfx );

    /* Push the Zip filter */
    if (opt.compress) {
	if (!compr_algo)
	    ; /* don't use compression */
	else {
	    if( old_style || compr_algo == 1 )
		zfx.algo = 1; /* use the non optional algorithm */
	    iobuf_push_filter( out, compress_filter, &zfx );
	}
    }

    /* Write the one-pass signature packets */
    /*(current filters: zip - encrypt - armor)*/
    if (!old_style) {
        rc = write_onepass_sig_packets (sk_list, out,
                                        opt.textmode? 0x01:0x00);
        if (rc)
            goto leave;
    }

    /* Pipe data through all filters; i.e. write the signed stuff */
    /*(current filters: zip - encrypt - armor)*/
    rc = write_plaintext_packet (out, inp, fname, opt.textmode ? 't':'b');
    if (rc)
	goto leave;
    
    /* Write the signatures */
    /*(current filters: zip - encrypt - armor)*/
    rc = write_signature_packets (sk_list, out, mfx.md,
                                  opt.textmode? 0x01 : 0x00,
                                  old_style, 'S');
    if( rc )
        goto leave;


  leave:
    if( rc )
	iobuf_cancel(out);
    else {
	iobuf_close(out);
        write_status( STATUS_END_ENCRYPTION );
    }
    iobuf_close(inp);
    release_sk_list( sk_list );
    md_close( mfx.md );
    m_free(cfx.dek);
    m_free(s2k);
    return rc;
}


/****************
 * Create a signature packet for the given public key certificate and
 * the user id and return it in ret_sig. User signature class SIGCLASS
 * user-id is not used (and may be NULL if sigclass is 0x20) If
 * DIGEST_ALGO is 0 the function selects an appropriate one.
 * SIGVERSION gives the minimal required signature packet version;
 * this is needed so that special properties like local sign are not
 * applied (actually: dropped) when a v3 key is used.
 */
int
make_keysig_packet( PKT_signature **ret_sig, PKT_public_key *pk,
		    PKT_user_id *uid, PKT_public_key *subpk,
		    PKT_secret_key *sk,
		    int sigclass, int digest_algo,
                    int sigversion,
		    int (*mksubpkt)(PKT_signature *, void *), void *opaque
		   )
{
    PKT_signature *sig;
    int rc=0;
    MD_HANDLE md;

    assert( (sigclass >= 0x10 && sigclass <= 0x13)
	    || sigclass == 0x20 || sigclass == 0x18
	    || sigclass == 0x30 || sigclass == 0x28 );

    if (sigversion < sk->version)
        sigversion = sk->version;

    if( !digest_algo ) {
	switch( sk->pubkey_algo ) {
	  case PUBKEY_ALGO_DSA: digest_algo = DIGEST_ALGO_SHA1; break;
	  case PUBKEY_ALGO_RSA_S:
	  case PUBKEY_ALGO_RSA: digest_algo = DIGEST_ALGO_MD5; break;
	  default:		digest_algo = DIGEST_ALGO_RMD160; break;
	}
    }
    md = md_open( digest_algo, 0 );

    /* hash the public key certificate and the user id */
    hash_public_key( md, pk );
    if( sigclass == 0x18 || sigclass == 0x28 ) { /* subkey binding/revocation*/
	hash_public_key( md, subpk );
    }
    else if( sigclass != 0x20 ) {
        hash_uid (md, sigversion, uid);
    }
    /* and make the signature packet */
    sig = m_alloc_clear( sizeof *sig );
    sig->version = sigversion;
    keyid_from_sk( sk, sig->keyid );
    sig->pubkey_algo = sk->pubkey_algo;
    sig->digest_algo = digest_algo;
    sig->timestamp = make_timestamp();
    sig->sig_class = sigclass;
    if( sig->version >= 4 )
	build_sig_subpkt_from_sig( sig );

    if( sig->version >= 4 && mksubpkt )
	rc = (*mksubpkt)( sig, opaque );

    if( !rc ) {
	mk_notation_and_policy( sig );
        hash_sigversion_to_magic (md, sig);
	md_final(md);

	rc = complete_sig( sig, sk, md );
    }

    md_close( md );
    if( rc )
	free_seckey_enc( sig );
    else
	*ret_sig = sig;
    return rc;
}



/****************
 * Create a new signature packet based on an existing one.
 * Only user ID signatures are supported for now.
 * TODO: Merge this with make_keysig_packet.
 */
int
update_keysig_packet( PKT_signature **ret_sig,
                      PKT_signature *orig_sig,
                      PKT_public_key *pk,
                      PKT_user_id *uid, 
                      PKT_secret_key *sk,
                      int (*mksubpkt)(PKT_signature *, void *),
                      void *opaque
		   )
{
    PKT_signature *sig;
    int rc=0;
    MD_HANDLE md;

    if (!orig_sig || !pk || !uid || !sk)
        return G10ERR_GENERAL;
    if (orig_sig->sig_class < 0x10 || orig_sig->sig_class > 0x13 )
        return G10ERR_GENERAL;

    md = md_open( orig_sig->digest_algo, 0 );

    /* hash the public key certificate and the user id */
    hash_public_key( md, pk );
    hash_uid (md, orig_sig->version, uid);

    /* create a new signature packet */
    sig = copy_signature (NULL, orig_sig);
    if ( sig->version >= 4 && mksubpkt)
	rc = (*mksubpkt)(sig, opaque);

    /* we increase the timestamp by one second so that a future import
       of this key will replace the existing one.  We also make sure that
       we don't create a timestamp in the future */
    sig->timestamp++; 
    while (sig->timestamp >= make_timestamp())
        sleep (1);
    /* put the updated timestamp back into the data */
    if( sig->version >= 4 )
	build_sig_subpkt_from_sig( sig );

    if (!rc) {
        hash_sigversion_to_magic (md, sig);
	md_final(md);

	rc = complete_sig( sig, sk, md );
    }

    md_close (md);
    if( rc )
	free_seckey_enc (sig);
    else
	*ret_sig = sig;
    return rc;
}


