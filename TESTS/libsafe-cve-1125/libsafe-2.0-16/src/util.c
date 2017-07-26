#ident "$Name: release2_0-16 $"
#ident "$Id: util.c,v 1.58 2002/05/30 14:44:38 ttsai Exp $"

/*
 * Copyright (C) 2002 Avaya Labs, Avaya Inc.
 * Copyright (C) 1999 Bell Labs, Lucent Technologies.
 * Copyright (C) Arash Baratloo, Timothy Tsai, and Navjot Singh.
 *
 * This file is part of the Libsafe library.
 * Libsafe version 2.x: protecting against stack smashing attacks.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * For more information, 
 *   visit http://www.research.avayalabs.com/project/libsafe/index.html
 *   or email libsafe@research.avayalabs.com
 */


#include <unistd.h>		/* defines readlink() */
#include <syslog.h>		/* defines syslog(3) */
#include <stdarg.h>		/* defines va_args */
#include <signal.h>		/* defines kill() */
#include <stdio.h>
#include <unistd.h>             /* defines pipe() */
#include <sys/resource.h>	/* defines RLIM_INFINITY */
#include <stdlib.h>
#include <sys/socket.h>
#include "util.h"
#include "log.h"

#define __USE_GNU		/* defines strnlen() */
#include <string.h>

// Sometimes environ is defined in unistd.h.  If so, then comment out the
// following declaration.
extern char **environ[];


/*****************************************************************************
 *
 * Miscellaneous functions.
 *
 *****************************************************************************/

static char *get_exename(char *exename, int size) {
    int res;
    
    /*
     * get the name of the current executable
     */
    if ((res = readlink("/proc/self/exe", exename, size - 1)) == -1)
	exename[0] = '\0';
    else
	exename[res] = '\0';
    return (exename);
}


/*
 * Has _libsafe_die() been called?
 */
static int dying = 0;


/*
 * Have we detected a stack with no frame pointers?  If so, we will assume that
 * we can bypass the libsafe checks for the entire process from that point on.
 */
extern int _libsafe_exclude;


#define PTHREAD_STACK_SIZE	(0x1fffff)
/*
 * Return the highest memory address associated with this addr.  This is just
 * a guess.  We assume that the main thread stack starts at 0xc0000000 and is
 * 8MB.  The other threads start at 0xbf800000 (immediately after the 8MB space
 * for the main thread stack) and are all 2MB.
 */
#define find_stack_start(addr)						    \
     /* Past stack area */						    \
    ((addr > (void*)0xc0000000) ? NULL :				    \
									    \
     /* Main thread stack */						    \
     (addr > (void*)0xbf800000) ? (void*)0xc0000000 :			    \
									    \
     /* Other thread stacks */						    \
	((void*)(((uint)addr & (~PTHREAD_STACK_SIZE)) + PTHREAD_STACK_SIZE))\
									    \
    )


/*****************************************************************************
 * 
 * These are functions that do the real work of determining if a libsafe
 * violation has occurred.
 *
 *****************************************************************************/

/* Given an address 'addr' returns 0 iff the address does not point to a stack
 * variable.  Otherwise, it returns a positive number indicating the number of
 * bytes (distance) between the 'addr' and the frame pointer it resides in.
 * Note: stack grows down, and arrays/structures grow up.
 */
uint _libsafe_stackVariableP(void *addr) {
    /*
     * bufsize is the distance between addr and the end of the stack frame.
     * It's what _libsafe_stackVariableP() is trying to calculate.
     */
    uint bufsize = 0;

    /*
     * (Vandoorselaere Yoann)
     * We have now just one cast.
     */
    void *fp, *sp;
    
    /*
     * nextfp is used in the check for -fomit-frame-pointer code.
     */
    void *nextfp;

    /*
     * stack_start is the highest address in the memory space mapped for this
     * stack.
     */
    void *stack_start;

    /*
     * If _libsafe_die() has been called, then we don't need to do anymore
     * libsafe checking.
     */
    if (dying)
	return 0;

    /*
     * (Arash Baratloo / Yoann Vandoorselaere)
     * use the stack address of the first declared variable to get the 'sp'
     * address in a portable way.
     */
    sp = &fp;

    /*
     * Stack grows downwards (toward 0x00).  Thus, if the stack pointer is
     * above (>) 'addr', 'addr' can't be on the stack.
     */
    if (sp > addr)
	return 0;

    /*
     * Note: the program name is always stored at 0xbffffffb (documented in the
     * book Linux Kernel).  Search back through the frames to find the frame
     * containing 'addr'.
     */
    fp = __builtin_frame_address(0);

    /*
     * Note that find_stack_start(fp) should never return NULL, since fp is
     * always guaranteed to be on the stack.
     */
    stack_start = find_stack_start((void*)&fp);

    while ((sp < fp) && (fp <= stack_start)) {
	if (fp > addr) {
	    /*
	     * found the frame -- now check the rest of the stack
	     */
	    bufsize = fp - addr;
	    break;
	}

	nextfp = *(void **) fp;

	/*
	 * The following checks are meant to detect code that doesn't insert
	 * frame pointers onto the stack.  (i.e., code that is compiled with
	 * -fomit-frame-pointer).
	 */

	/*
	 * Make sure frame pointers are word aligned.
	 */
	if ((uint)nextfp & 0x03) {
	    LOG(2, "fp not word aligned; bypass enabled\n");
	    _libsafe_exclude = 1;
	    return 0;
	}

	/*
	 * Make sure frame pointers are monotonically increasing.
	 */
	if (nextfp <= fp) {
	    LOG(2, "fp not monotonically increasing; bypass enabled\n");
	    _libsafe_exclude = 1;
	    return 0;
	}

	fp = nextfp;
    }

    /*
     * If we haven't found the correct frame by now, it either means that addr
     * isn't on the stack or that the stack doesn't contain frame pointers.
     * Either way, we will return 0 to bypass checks for addr.
     */
    if (bufsize == 0) {
	return 0;
    }

    /*
     * Now check to make sure that the rest of the stack looks reasonable.
     */
    while ((sp < fp) && (fp <= stack_start)) {
	nextfp = *(void **) fp;

	if (nextfp == NULL) {
	    /*
	     * This is the only correct way to end the stack.
	     */
	    return bufsize;
	}

	/*
	 * Make sure frame pointers are word aligned.
	 */
	if ((uint)nextfp & 0x03) {
	    LOG(2, "fp not word aligned; bypass enabled\n");
	    _libsafe_exclude = 1;
	    return 0;
	}

	/*
	 * Make sure frame pointers are monotonically * increasing.
	 */
	if (nextfp <= fp) {
	    LOG(2, "fp not monotonically increasing; bypass enabled\n");
	    _libsafe_exclude = 1;
	    return 0;
	}

	fp = nextfp;
    }

    /*
     * We weren't able to say for sure that the stack contains valid frame
     * pointers, so we will return 0, which means that no check for addr will
     * be done.
     */
    return 0;
}


/*
 * Save the return addresses and frame pointers into ra_array and fp_array.
 * Place the number of stack frames traversed into count.  Save at most
 * maxcount values into either ra_array or fp_array.  If maxcount is exceeded
 * (ie, ra_array[] and fp_array[] are too small) or the full set of values is
 * not stored, return -1; else return the count of items stores in ra_array or
 * fp_array.
 */
int _libsafe_save_ra_fp(int maxcount, caddr_t *ra_array, caddr_t *fp_array) {
    /*
     * How many values we have placed in ra[] or fp[].
     */
    int count = 0;

    /*
     * We will use these pointers to iterate through ra_array[] and fp_array[],
     * because that will be faster than using ra_array[index] notation.
     */
    caddr_t *ra_p = ra_array;
    caddr_t *fp_p = fp_array;

    /*
     * (Vandoorselaere Yoann)
     * We have now just one cast.
     */
    void *fp, *sp;
    
    /*
     * nextfp is used in the check for -fomit-frame-pointer code.
     */
    void *nextfp;

    /*
     * stack_start is the highest address in the memory space mapped for this
     * stack.
     */
    void *stack_start;

    /*
     * If _libsafe_die() has been called, then we don't need to do anymore
     * libsafe checking.
     */
    if (dying)
	return -1;

    /*
     * (Arash Baratloo / Yoann Vandoorselaere)
     * use the stack address of the first declared variable to get the 'sp'
     * address in a portable way.
     */
    sp = &fp;

    /*
     * We start saving at not this stack frame but the stack frame of the
     * function that called this function.
     */
    fp = __builtin_frame_address(1);

    /*
     * If fp <= sp, this means that we're not looking at the correct stack.
     */
    if (fp <= sp)
	return -1;

    /*
     * Note that find_stack_start(fp) should never return NULL, since fp is
     * always guaranteed to be on the stack.
     */
    stack_start = find_stack_start((void*)&fp);

    /*
     * Since we check to see if fp is monotonically increasing inside the while
     * loop, we don't need to check for it in the while predicate.
     */
    while ((fp <= stack_start)) {
	/*
	 * Make sure there's still enough space in ra[] and fp[] to store the
	 * values for the current stack frame.
	 */
	if (count+1 >= maxcount) {
	    return -1;
	}

	/*
	 * Store the current return address and frame pointer.  The return
	 * address will be the word immediately after the frame pointer.
	 */
	/*
	ra_array[count] = *(caddr_t*)(fp+sizeof(void*));
	fp_array[count++] = fp;
	*/



	*ra_p++ = *(caddr_t*)(fp+sizeof(void*));
	*fp_p++ = fp;
	count++;





	nextfp = *(void **) fp;

	if (nextfp == NULL) {
	    /*
	     * This is the only correct way to end the stack.
	     */
	    return count;
	}

	/*
	 * Make sure frame pointers are word aligned.
	 */
	if ((uint)nextfp & 0x03) {
	    LOG(2, "fp not word aligned; bypass enabled\n");
	    _libsafe_exclude = 1;
	    return -1;
	}

	/*
	 * Make sure frame pointers are monotonically * increasing.
	 */
	if (nextfp <= fp) {
	    LOG(2, "fp not monotonically increasing; bypass enabled\n");
	    _libsafe_exclude = 1;
	    return -1;
	}

	fp = nextfp;
    }

    /*
     * We weren't able to say for sure that the stack contains valid frame
     * pointers, so we will return -1.
     */
    return -1;
}


/*
 * Make sure that the current return addresses and frame pointers on the stack
 * match the values saved in ra_array and fp_array.  Return 0 if all values
 * match; or return 1 if the check was not completed; else return -1 if the
 * check was completed and failed.  count is the number of valid values in
 * ra_array and fp_array.
 *
 * Note that _libsafe_save_ra_fp() and _libsafe_verify_ra_fp() must be called
 * from within the same stack frame.
 */
int _libsafe_verify_ra_fp(int maxcount, caddr_t *ra_array, caddr_t *fp_array) {
    /*
     * Which stack frame are we currently looking at?
     */
    int count = 0;

    /*
     * We will use these pointers to iterate through ra_array[] and fp_array[],
     * because that will be faster than using ra_array[index] notation.
     */
    caddr_t *ra_p = ra_array;
    caddr_t *fp_p = fp_array;

    /*
     * (Vandoorselaere Yoann)
     * We have now just one cast.
     */
    void *fp, *sp;
    
    /*
     * nextfp is used in the check for -fomit-frame-pointer code.
     */
    void *nextfp;

    /*
     * stack_start is the highest address in the memory space mapped for this
     * stack.
     */
    void *stack_start;

    /*
     * If _libsafe_die() has been called, then we don't need to do anymore
     * libsafe checking.
     */
    if (dying)
	return 1;

    /*
     * (Arash Baratloo / Yoann Vandoorselaere)
     * use the stack address of the first declared variable to get the 'sp'
     * address in a portable way.
     */
    sp = &fp;

    /*
     * We start saving at not this stack frame but the stack frame of the
     * function that called this function.
     */
    fp = __builtin_frame_address(1);

    /*
     * If fp <= sp, this means that we're not looking at the correct stack.
     */
    if (fp <= sp)
	return -1;

    /*
     * Note that find_stack_start(fp) should never return NULL, since fp is
     * always guaranteed to be on the stack.
     */
    stack_start = find_stack_start((void*)&fp);

    while ((fp <= stack_start)) {
	/*
	 * Store the current return address and frame pointer.  The return
	 * address will be the word immediately after the frame pointer.
	 */
	/*
	if (ra_array[count] != *(caddr_t*)(fp+sizeof(void*)) ||
	    fp_array[count] != fp ||
	    count++ > maxcount)
	*/
	if (*ra_p++ != *(caddr_t*)(fp+sizeof(void*)) ||
	    *fp_p++ != fp ||
	    count++ > maxcount)
	{
	    /*
	     * Mismatch found!
	     */

	    /*
	     * In order to print out the true call stack, we need to restore
	     * the correct return addresses and frame pointers to the stack.
	     */
	    for (; count<maxcount; count++) {
		*(caddr_t*)(fp+sizeof(void*)) = ra_array[count];
		*(caddr_t*)fp = fp_array[count];
	    }

	    return -1;
	}

	nextfp = *(void **) fp;

	if (nextfp == NULL) {
	    /*
	     * This is the only correct way to end the stack.
	     */
	    return 0;
	}

	/*
	 * We don't need to verify that there are frame pointers on the stack,
	 * since we already did that when we called _libsafe_save_ra_fp().
	 */

	fp = nextfp;
    }

    /*
     * We weren't able to say for sure that the stack contains valid frame
     * pointers, so we will return -1.
     */
    return 1;
}


/*
 * Given an address 'addr' returns 1 iff the address points to a return address
 * or a frame pointer on the stack.  Otherwise, it returns 0.  Note: stack
 * grows down, and arrays/structures grow up.
 */
uint _libsafe_raVariableP(void *addr) {
    /*
     * Does addr point to a return address or a frame pointer on the stack?
     */
    int is_ra = 0;

    /*
     * (Vandoorselaere Yoann)
     * We have now just one cast.
     */
    void *fp, *sp;
    
    /*
     * nextfp is used in the check for -fomit-frame-pointer code.
     */
    void *nextfp;

    /*
     * stack_start is the highest address in the memory space mapped for this
     * stack.
     */
    void *stack_start;

    /*
     * If _libsafe_die() has been called, then we don't need to do anymore
     * libsafe checking.
     */
    if (dying)
	return 0;

    /*
     * (Arash Baratloo / Yoann Vandoorselaere)
     * use the stack address of the first declared variable to get the 'sp'
     * address in a portable way.
     */
    sp = &fp;

    /*
     * Stack grows downwards (toward 0x00).  Thus, if the stack pointer is
     * above (>) 'addr', 'addr' can't be on the stack.
     */
    if (sp > addr)
	return 0;

    /*
     * Note: the program name is always stored at 0xbffffffb (documented in the
     * book Linux Kernel).  Search back through the frames to find the frame
     * containing 'addr'.
     */
    fp = __builtin_frame_address(0);

    /*
     * Note that find_stack_start(fp) should never return NULL, since fp is
     * always guaranteed to be on the stack.
     */
    stack_start = find_stack_start((void*)&fp);

    while ((sp < fp) && (fp <= stack_start)) {
	if (fp == addr ||	    /* addr points to a frame pointer */
	    fp + 4 == addr)	    /* addr points to a return address */
	{
	    is_ra = 1;
	    break;
	}

	nextfp = *(void **) fp;

	/*
	 * The following checks are meant to detect code that doesn't insert
	 * frame pointers onto the stack.  (i.e., code that is compiled with
	 * -fomit-frame-pointer).
	 */

	/*
	 * Make sure frame pointers are word aligned.
	 */
	if ((uint)nextfp & 0x03) {
	    LOG(2, "fp not word aligned; bypass enabled\n");
	    return 0;
	}

	/*
	 * Make sure frame pointers are monotonically increasing.
	 */
	if (nextfp <= fp) {
	    LOG(2, "fp not monotonically increasing; bypass enabled\n");
	    return 0;
	}

	fp = nextfp;
    }

    /*
     * If we haven't found the correct frame by now, it either means that addr
     * isn't on the stack or that the stack doesn't contain frame pointers.
     * Either way, we will return 0 to bypass checks for addr.
     */
    if (is_ra == 0) {
	return 0;
    }

    /*
     * Now check to make sure that the rest of the stack looks reasonable.
     */
    while ((sp < fp) && (fp <= stack_start)) {
	nextfp = *(void **) fp;

	if (nextfp == NULL) {
	    /*
	     * This is the only correct way to end the stack.
	     */
	    return is_ra;
	}

	/*
	 * Make sure frame pointers are word aligned.
	 */
	if ((uint)nextfp & 0x03) {
	    LOG(2, "fp not word aligned; bypass enabled\n");
	    return 0;
	}

	/*
	 * Make sure frame pointers are monotonically * increasing.
	 */
	if (nextfp <= fp) {
	    LOG(2, "fp not monotonically increasing; bypass enabled\n");
	    return 0;
	}

	fp = nextfp;
    }

    /*
     * We weren't able to say for sure that the stack contains valid frame
     * pointers, so we will return 0.
     */
    return 0;
}


#ifdef DUMP_STACK
/* Create a new filename consisting for LIBSAFE_DUMP_STACK_FILE followed by the
 * PID.
 */
void create_dump_stack_filename(char *filename, int size) {
    char    *p, *p2;
    char    buf[10];	// To hold the PID, but with digits reversed.  We
			//	assume that the PID is at most 10 digits.
    int	    pid;
    int	    count=0;	// How many chars we already put into filename

    // strcpy(filename, LIBSAFE_DUMP_STACK_FILE);
    // NOTE:  We can't use strcpy or sprintf, since they will be intercepted by
    // libsafe and thus cause infinite recursion.
    for (p=LIBSAFE_DUMP_STACK_FILE,p2=filename; *p && count<size-1; p++) {
	*p2++ = *p;
	count++;
    }

    // strcat(filename, <getpid()>)
    // NOTE:  We can't use strcpy or sprintf, since they will be intercepted by
    // libsafe and thus cause infinite recursion.
    pid = getpid();
    for (p=buf; pid>0; p++) {
	*p = '0' + (pid % 10);
	pid /= 10;
    }
    for (p--; p>=buf && count<size-1; p--) {
	*p2++ = *p;
	count++;
    }

    *p2 = (char) NULL;
}

/* Print the stack contents to stderr.  Use the same approximations for sp (the
 * top of the stack) that _libsafe_stackVariableP() uses.
 */
void _libsafe_dump_stack(char *file, int linenum) {
    char    *sp;
    FILE    *fp=NULL;
    void    *current_stack_start;
    char    exename[MAXPATHLEN];

    /*
     * We will dump the stack contents into a file named
     * LIBSAFE_DUMP_STACK_FILE plus the PID of this process.  By tacking the
     * PID onto the filename, we allow a multi-threaded process to create stack
     * dump files that don't overwrite each other.
     */
    int	    filename_size = strlen(LIBSAFE_DUMP_STACK_FILE) + 6;
    char    *filename = alloca(filename_size);
    create_dump_stack_filename(filename, filename_size);
    
    /*
     * Note that find_stack_start(fp) should never return NULL, since fp is
     * always guaranteed to be on the stack.
     */
    current_stack_start = find_stack_start((void*)&fp);

    /*
     * (Arash Baratloo / Yoann Vandoorselaere)
     * use the stack address of the first declared variable to get the 'sp'
     * address in a portable way.
     */
    sp = (char*)&sp;

    if ((fp=fopen(filename, "w")) == NULL) {
	/* If we can't open the dump file, then just dump to stderr. */
	fp = stderr;
	LOG(1, "Dumping stack to stderr.\n");
    }
    else {
	LOG(1, "Dumping stack to %s.\n", filename);
    }




/* For debugging only!!! */
{
    char cmd[1000];
    sprintf(cmd, "cat /proc/%d/maps >/tmp/maps.%d", getpid(), getpid());
    system(cmd);
    printf("Copied maps to /tmp/maps.%d\n", getpid());
}






    fprintf(fp, "Stack dump:  sp=%p  fp=%p  stack_start=%p\n",
	sp, __builtin_frame_address(0), current_stack_start);
    fprintf(fp, "Initiating dump from file=%s linenum=%d\n", file, linenum);

    /*
     * get the name of the current executable
     */
    get_exename(exename, MAXPATHLEN);
    fprintf(fp, "Libsafe monitoring %s\n", exename);

    /*
     * This makes the fprintf below line up better.
     */
    sp = (char*)((uint)sp & (~0x7));

    /*
     * Print out the contents of the stack in hex, until 0x40 bytes past the
     * start of the stack.  Make sure we don't go past 0xbffffffb in any case
     * to avoid segfaults.
     */
    for (; sp<=(char*)current_stack_start+0x40 && sp<(char*)0xbffffffb; sp+=8) {
	fprintf(fp, "%p:  %02x %02x %02x %02x %02x %02x %02x %02x\n",
	    sp,
	    *sp & 0xff,
	    *(sp+1) & 0xff,
	    *(sp+2) & 0xff,
	    *(sp+3) & 0xff,
	    *(sp+4) & 0xff,
	    *(sp+5) & 0xff,
	    *(sp+6) & 0xff,
	    *(sp+7) & 0xff);
    }

    if (fp != stderr)
	fclose(fp);
}
#endif /* DUMP_STACK */

#ifdef NOTIFY_WITH_EMAIL

#include <netinet/in.h>
#include <arpa/inet.h>
#ifndef __USE_GNU
#define __USE_GNU 1		/* defines strnlen() */
#endif
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <time.h>

/*
* Read a single line of data (until the first newline) from the socket, and
* throw away the data.  The loglevel specifies what to do with the data read.
* <=0 means to throw the data away. >1 means to pass the data to LOG(loglevel,
* ...).
 */
static void clear_one_line(int s, int loglevel) {
    int	    res;
    char    throw_away_buf[500];

    while ((res=recv(s, throw_away_buf, sizeof(throw_away_buf)-1, 0)) > 0) {
	throw_away_buf[res] = (char)NULL;
	if (loglevel > 0)
	    LOG(loglevel, "%s\n", throw_away_buf);
	if (throw_away_buf[res-1] == '\n')
	    break;
    }
}

/*
 * Send the command to the mail server.  If the expected response is received,
 * return 0;  else return -1.  expected should be the first digit of the
 * 3-digit response code.  If expected==-1, then don't check the response.
 */
static int send_command(int s, int expected, char *format, ...) {
    char	response;
    char	command[2048];
    int	len, res;

    va_list args;

    /*
     * Form the command to send
     */
    va_start(args, format);
    len = vsnprintf(command, sizeof(command), format, args);
    va_end(args);

    /*
     * Send the command
     */
    res = send(s, command, len, 0);
    if (res == -1) {
	perror("libsafe:send_command:send()");
	return -1;
    }

    /*
     * Read the response from the mail server.  Make sure that the expected
     * response is received.  We only check the first digit from the 3-digit
     * response code.
     */
    if (expected >= 0) {
	if ((res=recv(s, &response, 1, 0)) > 0) {
	    if ((response - '0') != expected) {
		/*
		 * If we didn't get the expected response code, then read the
		 * full response code so we can print it out.
		 */
		char    full_response[4];

		full_response[0] = response;
		recv(s, &full_response[1], 2, 0);
		full_response[3] = (char)NULL;
		LOG(1, "Sendmail error: received %s, expected %dxx: ",
		    full_response, expected);
		syslog(LOG_CRIT, "Sendmail error: received %s, expected %dxx: ",
			full_response, expected);
		clear_one_line(s, 1);
		return -1;
	    }
	}

	/*
	 * We don't care about the rest of the response, so just read it and
	 * ignore it.
	 */
	clear_one_line(s, 0);
    }

    return 0;
}

/*
 * Same thing as ctime(), except that the trailing newline is truncated.
 */
char *ctime_nonewline(const time_t *timep) {
    char    *p;

    p = ctime(timep);

    /*
     * The last non-null char in the string p should be '\n'.  We will chop
     * that off the string.
     */
    p[strlen(p)-1] = (char)NULL;

    return p;
}

/*
 * Send email to the recipient, with the message as part of the subject.
 */
#define MAIL_PORT 25
static void sendmail(char *recipient, char *message) {
    struct sockaddr_in	addr;
    struct hostent	*hostinfo;
    int			s;
    char		hostname[100];
    time_t		t;

    /*
     * Get the name of the local machine.
     */
    if (gethostname(hostname, sizeof(hostname))) {
	strncpy(hostname, "localhost", sizeof(hostname));
    }

    /*
     * Find the current time.  This will be used as the send time for the
     * email.
     */
    time(&t);

    if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
	perror("libsafe:sendmail:socket()");
	return;
    }

    if ((hostinfo = gethostbyname("localhost")) == NULL) {
	syslog(LOG_CRIT, "%s,%d: gethostbyname: %s\n", __FILE__, __LINE__,
		hstrerror(h_errno));
    return;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = ((struct in_addr *)(hostinfo->h_addr))->s_addr;
    addr.sin_port        = htons(MAIL_PORT);
    addr.sin_family      = AF_INET;
    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
	perror("libsafe:sendmail:connect()");
	return;
    }

    /*
     * Read the response (response code 220) that is sent from simply opening
     * the connection.
     */
    clear_one_line(s, 0);
    
    /*
     * Send the commands to the sendmail port.  Note that ctime_nonewline() is
     * used instead of ctime() because some mail transport agents choke on the
     * '\n' returned by ctime().
     */
    if (send_command(s, 2, "HELO %s\r\n", hostname)) return;
    if (send_command(s, 2, "MAIL FROM:<libsafe@%s>\r\n", hostname)) return;
    if (send_command(s, 2, "RCPT TO:<%s>\r\n", recipient)) return;
    if (send_command(s, 3, "DATA\r\n")) return;
    if (send_command(s, -1,
	"Subject: ***** libsafe violation detected *****\r\n"
	"To: %s\r\n"
	"Date: %s\r\n"
	"\r\n"
	"Libsafe violation detected on %s at %s\r\n"
	"%s\r\n",
	recipient, ctime_nonewline(&t), hostname, ctime(&t), message))
	    return;
    if (send_command(s, 2, "\r\n.\r\n")) return;
    if (send_command(s, -1, "QUIT\r\n")) return;

    LOG(1, "Sent email to %s\n", recipient);
    syslog(LOG_CRIT, "Sent email to %s\n", recipient);
}
#endif	/* NOTIFY_WITH_EMAIL */



#ifdef HAVE_LIBPRELUDE

#include <grp.h>
#include <pwd.h>
#include <sys/types.h>
#include <string.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <libprelude/list.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/idmef-tree-func.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-message-buffered.h>
#include <libprelude/idmef-msg-send.h>
#include <libprelude/idmef-message-id.h>
#include <libprelude/sensor.h>
#include <sys/utsname.h>



static void get_stack_trace(const char *filename, char *buf, size_t size) 
{
        int ret;
        uint32_t pid;
        caddr_t	fp, ra;
        
        pid = getpid();
        
        ret = snprintf(buf, size,
		"Detected an attempt to write across stack boundary.\n"
		"Terminating %s.\n"
		"    uid=%d  euid=%d  pid=%d\n",
		filename, getuid(), geteuid(), pid);

        /*
         * Print out the call stack.  We can assume that the stack is a normal
         * stack, since _libsafe_stackVariableP(), _libsafe_raVariableP(), or
         * _libsafe_span_stack_frames() had to be called first.
         */
        ret += snprintf(buf + ret, size - ret, "Call stack:\n");
        for ( fp = __builtin_frame_address(0); *fp; fp = *(void **) fp ) {
                ra = *((caddr_t*)(fp+4));
                ret += snprintf(buf + ret, size - ret, "    %p\n",
			(caddr_t)((uint)ra-5));
        }
}



static int set_user_infos(idmef_user_t *user)
{
        struct passwd *uent;
        struct group *gent;
        idmef_userid_t *userid;
        uid_t uid, euid;
        gid_t gid, egid;

        uid = getuid();
        euid = geteuid();
        gid = getgid();
        egid = getegid();
        
        /*
         * real user id.
         */
        userid = idmef_user_userid_new(user);
        if (! userid )
                return -1;
        
        userid->type = original_user;
        userid->number = uid;
        
        uent = getpwuid(uid);
        if ( uent )
                idmef_string_set(&userid->name, uent->pw_name);
                
        /*
         * effective user id
         */
        userid = idmef_user_userid_new(user);
        if (! userid )
                return -1;
        
        userid->type = user_privs;
        userid->number = euid;
        uent = getpwuid(euid);
        if ( uent )
                idmef_string_set(&userid->name, uent->pw_name);

        /*
         * real group id
         */
        userid = idmef_user_userid_new(user);
        if (! userid )
                return -1;
        
        userid->type = current_group;
        userid->number = gid;
        gent = getgrgid(gid);
        if ( gent )
                idmef_string_set(&userid->name, gent->gr_name);
        
        /*
         * Effective group id
         */
        userid = idmef_user_userid_new(user);
        if (! userid )
                return -1;
        
        userid->type = group_privs;
        userid->number = egid;
        gent = getgrgid(egid);
        if ( gent )
                idmef_string_set(&userid->name, gent->gr_name);

        return 0;
}




static void fill_assessment(idmef_assessment_t *assessment) 
{
        idmef_action_t *action;
        
        idmef_assessment_impact_new(assessment);
        
        assessment->impact->severity = impact_high;
        assessment->impact->completion = failed;
        assessment->impact->type = admin;

        if ( getuid() == 0 || geteuid() == 0 )
                assessment->impact->type = admin;
        else
                assessment->impact->type = user;
        
        idmef_string_set_constant(&assessment->impact->description,
		"Stack overflow attempt detected and avoided by libsafe");
        idmef_assessment_confidence_new(assessment);
        assessment->confidence->rating = high;

        action = idmef_assessment_action_new(assessment);
        if ( ! action )
                return;

        action->category = taken_offline;
        idmef_string_set_constant(&action->description,
		"Libsafe killed the target process in order to prevent the "
		"overflow attack from succeeding");
}





static void prelude_alert(char *filename) 
{
        int ret;
        char *program;
        idmef_user_t *user;
        idmef_alert_t *alert;
        struct utsname utsbuf;
        idmef_message_t *idmef;
        idmef_target_t *target;
        idmef_process_t *process;
        prelude_msgbuf_t *msgbuf;
        char buf[8192], hostname[255];
        idmef_additional_data_t *data;
        idmef_classification_t *classification;        
        
        
        ret = prelude_sensor_init("libsafe", NULL, 0, NULL);
        if ( ret < 0 ) {
                fprintf(stderr, "couldn't initialize the Prelude library\n");
                return;
        }

        /*
         * separate program name from pathname.
         */
        program = strrchr(filename, '/');
        if ( program ) {
                *program = '\0';
                program++;
        }
        
        get_stack_trace(filename, buf, sizeof(buf));
        
        idmef = idmef_message_new();
        if ( ! idmef )
                return;

        /*
         * fill alert / analyzer informations
         */
        idmef_alert_new(idmef);
        alert = idmef->message.alert;
        idmef_alert_assessment_new(alert);

        fill_assessment(alert->assessment);
        
        idmef_string_set_constant(&alert->analyzer.model, "Libsafe");
        idmef_string_set_constant(&alert->analyzer.class,
		"Stack Overflow Detection Library");
        idmef_string_set_constant(&alert->analyzer.version, VERSION);

        /*
         * Fill analyzer process informations.
         */
        idmef_analyzer_process_new(&alert->analyzer);
        alert->analyzer.process->pid = getpid();
        idmef_string_set(&alert->analyzer.process->name, program);
        idmef_string_set(&alert->analyzer.process->path, filename);

        ret = uname(&utsbuf);
        if ( ret < 0 )
                goto err;

        idmef_string_set(&alert->analyzer.ostype, utsbuf.sysname);
        idmef_string_set(&alert->analyzer.osversion, utsbuf.release);

        /*
         * Fill analyzer node infomations.
         */
        idmef_analyzer_node_new(&alert->analyzer);
        gethostname(hostname, sizeof(hostname));
        idmef_string_set(&alert->analyzer.node->name, hostname);

        /*
         * target informations
         */
        target = idmef_alert_target_new(alert);
        if ( ! target )
                goto err;

        user = idmef_target_user_new(target);
        if ( ! user )
                goto err;
        
        user->category = application;
        
        ret = set_user_infos(user);
        if ( ret < 0 )
                goto err;
        
        process = idmef_target_process_new(target);
        idmef_string_set(&process->name, program);
        process->pid  = getpid();
        idmef_string_set(&process->path, filename);

        /*
         * Attack classification
         */
        classification = idmef_alert_classification_new(alert);
        if ( ! classification )
                goto err;

        idmef_string_set_constant(&classification->name,
		"Stack Overflow Attempt");

        /*
         * Include the call trace.
         */
        data = idmef_alert_additional_data_new(alert);
        if ( ! data )
                goto err;
        
        data->type = string;
        idmef_string_set_constant(&data->meaning, "Stack overflow data");
        idmef_additional_data_set_data(data, string, buf, strlen(buf) + 1);

        /*
         * send the message synchronously (use 1 for asynchronous send).
         */
        msgbuf = prelude_msgbuf_new(0);
        if ( ! msgbuf )
                goto err;
        
        idmef_msg_send(msgbuf, idmef, PRELUDE_MSG_PRIORITY_HIGH);
        idmef_message_free(idmef);
        prelude_msgbuf_close(msgbuf);
        
        return;
        
  err:
        idmef_message_free(idmef);
        LOG(1, "error writing an IDMEF message.\n");
}

#endif /* NOTIFY_WITH_PRELUDE */


/*
 * Sanity check for stack frame pointers.  Return 0 if the check passes.  Else
 * return 1.
 */
static int check_nextfp(caddr_t fp, caddr_t nextfp) {
    caddr_t stack_start = find_stack_start((void*)&fp);

    /*
     * The following checks are meant to detect code that doesn't insert
     * frame pointers onto the stack.  (i.e., code that is compiled with
     * -fomit-frame-pointer).
     */

    if (nextfp > stack_start) {
	LOG(2, "fp > stack_start; bypass enabled\n");
	_libsafe_exclude = 1;
	return 1;
    }

    /*
     * Make sure frame pointers are word aligned.
     */
    if ((uint)nextfp & 0x03) {
	LOG(2, "fp not word aligned; bypass enabled\n");
	_libsafe_exclude = 1;
	return 1;
    }

    /*
     * Make sure frame pointers are monotonically increasing.
     */
    if (nextfp <= fp) {
	LOG(2, "fp not monotonically increasing; bypass enabled\n");
	_libsafe_exclude = 1;
	return 1;
    }

    return 0;
}


struct maps_st {
    caddr_t start, end;
    char    *path;
};


/*
 * Read /proc/<pid>/maps to find the memory-mapped regions for this process.
 */
static int get_memory_maps(struct maps_st **mapsptr) {
    struct maps_st  *maps = NULL;
    char    filename[200], buf[500];
    FILE    *fp;
    int	    count, i;
    char    *p;

    snprintf(filename, sizeof(filename), "/proc/%d/maps", getpid());

    /*
     * First pass:  Find out how many memory regions there are.
     */
    if ((fp=fopen(filename, "r")) == NULL) {
	return 0;
    }

    count = 0;
    while (fgets(buf, sizeof(buf), fp)) {
	count++;
    }

    fclose(fp);

    maps = (struct maps_st *) malloc(count * sizeof(struct maps_st));
    *mapsptr = maps;

    /*
     * Second pass:  Fill in the table with the region info.
     */
    if ((fp=fopen(filename, "r")) == NULL) {
	if (maps) free(maps);
	return 0;
    }

    i = 0;
    while (fgets(buf, sizeof(buf), fp) && i < count) {
	sscanf(buf, "%p-%p", &maps[i].start, &maps[i].end);
	p = strchr(buf, '/');
	if (p) {
	    maps[i].path = strdup(p);
	    
	    /*
	     * Strip off the trailing newline.
	     */
	    p = strchr(maps[i].path, '\n');
	    if (p) *p = (char)NULL;
	}
	else
	{
	    maps[i].path = NULL;
	}
	i++;
    }

    fclose(fp);

    return count;
}


/*
 * Return the index into the maps array that corresponds to the caller_addr.
 * If caller_addr is not in any of the regions in maps, then return -1.
 */
static int find_caller_addr(struct maps_st *maps, int count, caddr_t
	caller_addr)
{
    int	i;

    for (i=0; i<count; i++) {
	if (caller_addr >= maps[i].start && caller_addr <= maps[i].end)
	    return i;
    }

    return -1;
}


/*
 * This is what is called when a violation is detected.  If you want to add
 * customized actions triggered by detection put them here.  (format,...) is
 * similar to printf() and passed to syslog().
 */
void _libsafe_warn(char *format, ...)
{
    char    exename[MAXPATHLEN];
    va_list args;
    struct maps_st	*maps;
    int		count, index;

    dying = 1;

    /*
     * get the name of the current executable
     */
    get_exename(exename, MAXPATHLEN);
    
    va_start(args, format);

    count = get_memory_maps(&maps);

    /*
     * add an entry to syslog()
     */
#ifdef DEBUG_TURN_OFF_SYSLOG
    LOG(1, "Turned off syslog entries for debugging.\n");
#else
    openlog(LIBNAME, LOG_CONS | LOG_PID, LOG_AUTHPRIV);
    syslog(LOG_CRIT, "Libsafe version %s", VERSION);
    syslog(LOG_CRIT, "Detected an attempt to write across stack boundary.");
    syslog(LOG_CRIT, "Terminating %s.", exename);
    syslog(LOG_CRIT, "    uid=%d  euid=%d  pid=%d", getuid(), geteuid(),
	    getpid());
#endif
    LOG(1, "Libsafe version %s\n", VERSION);
    LOG(1, "Detected an attempt to write across stack boundary.\n");
    LOG(1, "Terminating %s.\n", exename);
    LOG(1, "    uid=%d  euid=%d  pid=%d\n", getuid(), geteuid(), getpid());

    {
	/*
	 * Print out the call stack.  We can assume that the stack is a normal
	 * stack, since _libsafe_stackVariableP(), _libsafe_raVariableP(), or
	 * _libsafe_span_stack_frames() had to be called first.
	 */
	caddr_t	fp, ra, nextfp, caller_addr;
#ifndef DEBUG_TURN_OFF_SYSLOG
	syslog(LOG_CRIT, "Call stack:\n");
#endif
	LOG(1, "Call stack:\n");

	for (fp=__builtin_frame_address(0); *fp; fp=nextfp) {
	    ra = *((caddr_t*)(fp+4));

	    /*
	     * Find the memory region and corresponding mapped file associated
	     * with this address.
	     */
	    caller_addr = (caddr_t)((uint)ra-5);
	    index = find_caller_addr(maps, count, caller_addr);

#ifndef DEBUG_TURN_OFF_SYSLOG
	    syslog(LOG_CRIT, "    %p  %s\n", caller_addr, maps[index].path);
#endif
	    LOG(1, "    %p\t%s\n", caller_addr, maps[index].path);

	    nextfp = *(void **)fp;
	    if (check_nextfp(fp, nextfp))
		break;
	}
    }
#ifndef DEBUG_TURN_OFF_SYSLOG
    syslog(LOG_CRIT, format, args);
#endif
    if (1 <= LOG_LEVEL) {
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
    }

    va_end(args);

    /*
     * PUT ANY CUSTOMIZED ACTIONS HERE...
     */

#ifdef HAVE_LIBPRELUDE
    prelude_alert(exename);
#endif
    
#ifdef DUMP_STACK
    /* Print the contents of the stack */
    _libsafe_dump_stack(__FILE__, __LINE__);
#endif

#ifdef NOTIFY_WITH_EMAIL
    {
	char errmsg[1000];
	char buf[1000];
	char recipient[500];
	FILE *fp;

	/*
	 * Form the descriptive message.
	 */
	snprintf(errmsg, sizeof(errmsg),
	    "Libsafe version %s\r\n"
	    "Detected an attempt to write across stack boundary.\r\n"
	    "Terminating %s.\r\n"
	    "    uid=%d  euid=%d  pid=%d\r\n",
	    VERSION,
	    exename,
	    getuid(), geteuid(), getpid());
	{
	    /*
	     * Print out the call stack.  We can assume that the stack is a
	     * normal stack, since _libsafe_stackVariableP(),
	     * _libsafe_raVariableP(), or _libsafe_span_stack_frames() had to
	     * be called first.
	     */
	    caddr_t	fp, ra, nextfp, caller_addr;
	    struct maps_st	*maps;
	    int		count, index;

	    count = get_memory_maps(&maps);

	    snprintf(buf, sizeof(buf), "Call stack:\r\n");
	    strncat(errmsg, buf,
		sizeof(errmsg) - strnlen(errmsg,sizeof(errmsg)) - 1);
	    for (fp=__builtin_frame_address(0); *fp; fp=nextfp) {
		ra = *((caddr_t*)(fp+4));

		/*
		 * Find the memory region and corresponding mapped file
		 * associated with this address.
		 */
		caller_addr = (caddr_t)((uint)ra-5);
		index = find_caller_addr(maps, count, caller_addr);

		snprintf(buf, sizeof(buf), "    %p\t%s\r\n", caller_addr,
			maps[index].path);
		strncat(errmsg, buf,
		    sizeof(errmsg) - strnlen(errmsg,sizeof(errmsg)) - 1);

		nextfp = *(void **)fp;
		if (check_nextfp(fp, nextfp))
		    break;
	    }
	}
#ifdef DUMP_STACK
	{
	    /*
	     * We will dump the stack contents into a file named
	     * LIBSAFE_DUMP_STACK_FILE plus the PID of this process.  By
	     * tacking the PID onto the filename, we allow a multi-threaded
	     * process to create stack dump files that don't overwrite each
	     * other.
	     */
	    int	    filename_size = strlen(LIBSAFE_DUMP_STACK_FILE) + 6;
	    char    *filename = alloca(filename_size);
	    create_dump_stack_filename(filename, filename_size);
	    snprintf(buf, sizeof(buf), "Dumped stack to %s.\r\n", filename);
	    strncat(errmsg, buf,
		sizeof(errmsg) - strnlen(errmsg,sizeof(errmsg)) - 1);
	}
#endif
    
	va_start(args, format);
	vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);
	strncat(errmsg, buf,
	    sizeof(errmsg) - strnlen(errmsg,sizeof(errmsg)) - 1);

	/*
	 * If the mail_list file exists, then send email to all the recipients
	 * listed in that file.  Otherwise, send email to root@localhost.
	 */
	if ((fp = fopen("/etc/libsafe.notify", "r")) == NULL) {
	    sendmail("root@localhost", errmsg);
	} else {
	    while (fgets(recipient, sizeof(recipient), fp)) {
		char *p;

		/*
		 * Chop off any trailing newlines if present
		 */
		for (p=recipient + strnlen(recipient, sizeof(recipient)) - 1;
		     isspace(*p);
		     p--)
		{
		    *p = (char) NULL;
		}
		
		sendmail(recipient, errmsg);
	    }
	    fclose(fp);
	}
    }
#endif	/* NOTIFY_WITH_EMAIL */

    if (maps)
	free(maps);

    /*
     * Since we are justing doing a warning, set dying=0 to indicate that we
     * should resume libsafe checking now.
     */
    dying = 0;
}

/*
 * This is what is called when a buffer overflow on the stack is detected.  If
 * you want to add customized actions triggered by detection put them here.
 * 'name' is the name of this library, and (format,...) is similar to printf()
 * and passed to syslog().
 */
void _libsafe_die(char *format, ...)
{
    va_list args;

    dying = 1;

    va_start(args, format);
    _libsafe_warn(format, args);
    va_end(args);

#ifdef DUMP_CORE
    /*
     * Kill this process, but generate a core dump in the /tmp directory.  If
     * there is no /tmp directory, the core dump is placed in the current
     * working directory, wherever that is.
     *
     * signal() is needed to disabled any registered handlers for SIGABRT,
     * which is used by abort().  Doing a chdir("/tmp") makes it easier to find
     * where the core dump file is.  However, if /tmp/core already exists and
     * is owned by another user, then no core dump file will be generated.
     */
    signal(SIGABRT, SIG_IGN);
    if (chdir("/tmp")) {
	LOG(1, "Dumping core to /tmp.");
    }
    else {
	char dirname[100];
	getcwd(dirname, sizeof(dirname));
	LOG(1, "Dumping core to %s.\n", dirname);
    }
    {
    /*
     * setrlimit() makes sure that we can produce a core dump file.
     */
    struct rlimit rlim = {0, RLIM_INFINITY};
    setrlimit(RLIMIT_CORE, &rlim);
    }
    abort();
#else
    /*
     * (Vandoorselaere Yoann)
     * let's do that in a cleaner way, don't use code to generate sigsegv cause
     * it can be handled... use _exit().
     *
     * _exit() doesn't kill multi-threaded processes properly, so now we use
     * SIGKILL.  There might be a concern with delayed signal delivery, but at
     * least it kills all threads and can't be caught. -- tkt
     */
    //_exit(1);
    raise(SIGKILL);
#endif
}


