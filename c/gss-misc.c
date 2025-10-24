/*
 * Copyright 1994 by OpenVision Technologies, Inc.
 * 
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 * 
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */



#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#ifdef Darwin
#include <GSS/gssapi.h>
#else
#include <gssapi/gssapi.h>
#endif

#include "gss-misc.h"

#include <stdlib.h>

FILE *display_file;

static void display_status_1(char *m, OM_uint32 code, int type);

static int write_all(int fildes, char *buf, unsigned int nbyte)
{
     int ret;
     char *ptr;

     for (ptr = buf; nbyte; ptr += ret, nbyte -= ret) {
          ret = write(fildes, ptr, nbyte);
          if (ret < 0) {
               if (errno == EINTR)
                    continue;
               return(ret);
          } else if (ret == 0) {
               return(ptr-buf);
          }
     }

     return(ptr-buf);
}

static int read_all(int fildes, char *buf, unsigned int nbyte)
{
     int ret;
     char *ptr;

     for (ptr = buf; nbyte; ptr += ret, nbyte -= ret) {
          ret = read(fildes, ptr, nbyte);
          if (ret < 0) {
               if (errno == EINTR)
                    continue;
               return(ret);
          } else if (ret == 0) {
               return(ptr-buf);
          }
     }

     return(ptr-buf);
}

/*
 * Function: send_token
 *
 * Purpose: Writes a token to a file descriptor.
 *
 * Arguments:
 *
 *      s               (r) an open file descriptor
 *      tok             (r) the token to write
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 *
 * send_token writes the token length (as a network long) and then the
 * token data to the file descriptor s.  It returns 0 on success, and
 * -1 if an error occurs or if it could not write all the data.
 */
int send_token(int s, gss_buffer_t tok)
{
     int len, ret;

     len = htonl(tok->length);

     ret = write_all(s, (char *) &len, 4);
     if (ret < 0) {
          perror("sending token length");
          return -1;
     } else if (ret != 4) {
         if (display_file)
             fprintf(display_file, 
                     "sending token length: %d of %d bytes written\n", 
                     ret, 4);
          return -1;
     }

     ret = write_all(s, tok->value, tok->length);
     if (ret < 0) {
          perror("sending token data");
          return -1;
     } else if (ret != tok->length) {
         if (display_file)
             fprintf(display_file, 
                     "sending token data: %d of %ld bytes written\n", 
                     ret, tok->length);
         return -1;
     }
     
     return 0;
}

/*
 * Function: recv_token
 *
 * Purpose: Reads a token from a file descriptor.
 *
 * Arguments:
 *
 *      s               (r) an open file descriptor
 *      tok             (w) the read token
 *
 * Returns: 0 on success, -1 on failure
 *
 * Effects:
 * 
 * recv_token reads the token length (as a network long), allocates
 * memory to hold the data, and then reads the token data from the
 * file descriptor s.  It blocks to read the length and data, if
 * necessary.  On a successful return, the token should be freed with
 * gss_release_buffer.  It returns 0 on success, and -1 if an error
 * occurs or if it could not read all the data.
 */
int recv_token(int s, gss_buffer_t tok)
{
     int ret;

     ret = read_all(s, (char *) &tok->length, 4);
     if (ret < 0) {
          perror("reading token length");
          return -1;
     } else if (ret != 4) {
         if (display_file)
             fprintf(display_file, 
                     "reading token length: %d of %d bytes read\n", 
                     ret, 4);
         return -1;
     }
          
     tok->length = ntohl(tok->length);
     tok->value = (char *) malloc(tok->length);
     if (tok->value == NULL) {
         if (display_file)
             fprintf(display_file, 
                     "Out of memory allocating token data\n");
          return -1;
     }

     ret = read_all(s, (char *) tok->value, tok->length);
     if (ret < 0) {
          perror("reading token data");
          free(tok->value);
          return -1;
     } else if (ret != tok->length) {
          fprintf(stderr, "sending token data: %d of %ld bytes written\n", 
                  ret, tok->length);
          free(tok->value);
          return -1;
     }

     return 0;
}

static void display_status_1(char *m, OM_uint32 code, int type)
{
     OM_uint32 min_stat;
     gss_buffer_desc msg;
     OM_uint32 msg_ctx;
     
     msg_ctx = 0;
     while (1) {
          gss_display_status(&min_stat, code,
                                       type, GSS_C_NULL_OID,
                                       &msg_ctx, &msg);
          if (display_file)
              fprintf(display_file, "GSS-API error %s: %s\n", m,
                      (char *)msg.value); 
          (void) gss_release_buffer(&min_stat, &msg);
          
          if (!msg_ctx)
               break;
     }
}

/*
 * Function: display_status
 *
 * Purpose: displays GSS-API messages
 *
 * Arguments:
 *
 *      msg             a string to be displayed with the message
 *      maj_stat        the GSS-API major status code
 *      min_stat        the GSS-API minor status code
 *
 * Effects:
 *
 * The GSS-API messages associated with maj_stat and min_stat are
 * displayed on stderr, each preceded by "GSS-API error <msg>: " and
 * followed by a newline.
 */
void display_status(char *msg, OM_uint32 maj_stat, OM_uint32 min_stat)
{
     display_status_1(msg, maj_stat, GSS_C_GSS_CODE);
     display_status_1(msg, min_stat, GSS_C_MECH_CODE);
}

/*
 * Function: display_ctx_flags
 *
 * Purpose: displays the flags returned by context initiation in
 *          a human-readable form
 *
 * Arguments:
 *
 *      int             ret_flags
 *
 * Effects:
 *
 * Strings corresponding to the context flags are printed on
 * stdout, preceded by "context flag: " and followed by a newline
 */

void display_ctx_flags(OM_uint32 flags)
{
     fprintf(display_file, "Context flags:\n");
     if (flags & GSS_C_DELEG_FLAG)
          fprintf(display_file, " GSS_C_DELEG_FLAG\n");
     if (flags & GSS_C_MUTUAL_FLAG)
          fprintf(display_file, " GSS_C_MUTUAL_FLAG\n");
     if (flags & GSS_C_REPLAY_FLAG)
          fprintf(display_file, " GSS_C_REPLAY_FLAG\n");
     if (flags & GSS_C_SEQUENCE_FLAG)
          fprintf(display_file, " GSS_C_SEQUENCE_FLAG\n");
     if (flags & GSS_C_CONF_FLAG )
          fprintf(display_file, " GSS_C_CONF_FLAG \n");
     if (flags & GSS_C_INTEG_FLAG )
          fprintf(display_file, " GSS_C_INTEG_FLAG \n");
}

void print_token(gss_buffer_t tok)
{
    int i;
    unsigned char *p = tok->value;

    if (!display_file)
        return;
    for (i=0; i < tok->length; i++, p++) {
        fprintf(display_file, "%02x ", *p);
        if ((i % 16) == 15) {
            fprintf(display_file, "\n");
        }
    }
    fprintf(display_file, "\n");
    fflush(display_file);
}

#define GSS_EMPTY_BUFFER(buf)   ((buf) == NULL ||                       \
                                 (buf)->value == NULL || (buf)->length == 0)

static int
get_arc(const unsigned char **bufp, const unsigned char *end,
        unsigned long *arc_out)
{
    const unsigned char *p = *bufp;
    unsigned long arc = 0, newval;

    if (p == end || !isdigit(*p))
        return 0;
    for (; p < end && isdigit(*p); p++) {
        newval = arc * 10 + (*p - '0');
        if (newval < arc)
            return 0;
        arc = newval;
    }
    while (p < end && (isspace(*p) || *p == '.'))
        p++;
    *bufp = p;
    *arc_out = arc;
    return 1;
}

static size_t
arc_encoded_length(unsigned long arc)
{
    size_t len = 1;

    for (arc >>= 7; arc; arc >>= 7)
        len++;
    return len;
}

static void
arc_encode(unsigned long arc, unsigned char **bufp)
{
    unsigned char *p;

    /* Advance to the end and encode backwards. */
    p = *bufp = *bufp + arc_encoded_length(arc);
    *--p = arc & 0x7f;
    for (arc >>= 7; arc; arc >>= 7)
        *--p = (arc & 0x7f) | 0x80;
}

OM_uint32
_gss_str_to_oid(OM_uint32 *minor_status,
                       gss_buffer_t oid_str,
                       gss_OID *oid_out)
{
    const unsigned char *p, *end, *arc3_start;
    unsigned char *out;
    unsigned long arc, arc1, arc2;
    size_t nbytes;
    int brace = 0;
    gss_OID oid;

    *minor_status = 0;

    if (oid_out != NULL)
        *oid_out = GSS_C_NO_OID;

    if (GSS_EMPTY_BUFFER(oid_str))
        return (GSS_S_CALL_INACCESSIBLE_READ);

    if (oid_out == NULL)
        return (GSS_S_CALL_INACCESSIBLE_WRITE);

    /* Skip past initial spaces and, optionally, an open brace. */
    brace = 0;
    p = oid_str->value;
    end = p + oid_str->length;
    while (p < end && isspace(*p))
        p++;
    if (p < end && *p == '{') {
        brace = 1;
        p++;
    }
    while (p < end && isspace(*p))
        p++;

    /* Get the first two arc values, to be encoded as one subidentifier. */
    if (!get_arc(&p, end, &arc1) || !get_arc(&p, end, &arc2))
        return (GSS_S_FAILURE);
    if (arc1 > 2 || (arc1 < 2 && arc2 > 39) || arc2 > ULONG_MAX - 80)
        return (GSS_S_FAILURE);
        arc3_start = p;

        /* Compute the total length of the encoding while checking syntax. */
        nbytes = arc_encoded_length(arc1 * 40 + arc2);
        while (get_arc(&p, end, &arc))
            nbytes += arc_encoded_length(arc);
        if (brace && (p == end || *p != '}'))
            return (GSS_S_FAILURE);
    
        /* Allocate an oid structure. */
        oid = malloc(sizeof(*oid));
        if (oid == NULL)
            return (GSS_S_FAILURE);
        oid->elements = malloc(nbytes);
        if (oid->elements == NULL) {
            free(oid);
            return (GSS_S_FAILURE);
        }
        oid->length = nbytes;
    
        out = oid->elements;
        arc_encode(arc1 * 40 + arc2, &out);
        p = arc3_start;
        while (get_arc(&p, end, &arc))
            arc_encode(arc, &out);
        assert(out - nbytes == oid->elements);
        *oid_out = oid;
        return(GSS_S_COMPLETE);
}     