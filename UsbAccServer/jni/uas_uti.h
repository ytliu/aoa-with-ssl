#undef NDEBUG

#define LOGTAG "uas_uti"

#define uas_STATE_INITIAL 0
#define uas_STATE_STARTIN 1
#define uas_STATE_STARTED 2
#define uas_STATE_STOPPIN 3
#define uas_STATE_STOPPED 4

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

#include <string.h>
#include <signal.h>

#include <pthread.h>

#include <errno.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <dirent.h> // For opendir (), readdir (), closedir (), DIR, struct dirent.

extern int ena_log_extra;
extern int ena_log_verbo;
extern int ena_log_send;

#define byte unsigned char
#define DEFBUF  65536 // Default buffer size is maximum for USB

#define DEF_BUF 512 // For Ascii strings and such


#ifdef __ANDROID_API__
#include <android/log.h>
#else
// UNKNOWN    0
#define ANDROID_LOG_DEFAULT 1
#define ANDROID_LOG_VERBOSE 2
#define ANDROID_LOG_DEBUG   3
// INFO       4
#define ANDROID_LOG_WARN    5
#define ANDROID_LOG_ERROR   6
// FATAL      7
// SILENT     8
#endif

#define uas_LOG_EXT   ANDROID_LOG_DEFAULT
#define uas_LOG_VER   ANDROID_LOG_VERBOSE
#define uas_LOG_DEB   ANDROID_LOG_DEBUG
#define uas_LOG_WAR   ANDROID_LOG_WARN
#define uas_LOG_ERR   ANDROID_LOG_ERROR

#ifdef NDEBUG

#define  logd(...)

#else

#define  logd(...)  uas_log(uas_LOG_DEB,LOGTAG,__func__,__VA_ARGS__)

#endif

int uas_log (int prio, const char * tag, const char * func, const char * fmt, ...);

unsigned long ms_get();
unsigned long ms_sleep(unsigned long ms);

#ifndef __ANDROID_API__
#define strlcpy   strncpy
#define strlcat   strncat
#endif

#ifdef  DONT_USE
#ifndef HAVE_STRLCAT
/*
 * '_cups_strlcat()' - Safely concatenate two strings.
 */

size_t                  /* O - Length of string */
strlcat(char *dst,        /* O - Destination string */
    const char *src,      /* I - Source string */
    size_t     size)      /* I - Size of destination string buffer */
{
  size_t    srclen;         /* Length of source string */
  size_t    dstlen;         /* Length of destination string */


  /*
   * Figure out how much room is left...
   */

  dstlen = strlen(dst);
  size   -= dstlen + 1;

  if (!size)
    return (dstlen);        /* No room, return immediately... */

  /*
   * Figure out how much room is needed...
   */

  srclen = strlen(src);

  /*
   * Copy the appropriate amount...
   */

  if (srclen > size)
    srclen = size;

  memcpy(dst + dstlen, src, srclen);
  dst[dstlen + srclen] = '\0';

  return (dstlen + srclen);
}
#endif /* !HAVE_STRLCAT */

#ifndef HAVE_STRLCPY
/*
 * '_cups_strlcpy()' - Safely copy two strings.
 */

size_t                  /* O - Length of string */
strlcpy(char *dst,        /* O - Destination string */
    const char *src,      /* I - Source string */
    size_t      size)     /* I - Size of destination string buffer */
{
  size_t    srclen;         /* Length of source string */


  /*
   * Figure out how much room is needed...
   */

  size --;

  srclen = strlen(src);

  /*
   * Copy the appropriate amount...
   */

  if (srclen > size)
    srclen = size;

  memcpy(dst, src, srclen);
  dst[srclen] = '\0';

  return (srclen);
}
#endif /* !HAVE_STRLCPY */

#endif


// Android USB device priority:


#define USB_VID_GOO 0x18D1    // The vendor ID should match Google's ID ( 0x18D1 ) and the product ID should be 0x2D00 or 0x2D01 if the device is already in accessory mode (case A).

#define USB_VID_HTC 0x0bb4
#define USB_VID_MOT 0x22b8

#define USB_VID_SAM 0x04e8
#define USB_VID_O1A 0xfff6  // Samsung ?

#define USB_VID_SON 0x0fce
#define USB_VID_LGE 0xfff5

#define USB_VID_LIN 0x1d6b
#define USB_VID_QUA 0x05c6
#define USB_VID_COM 0x1519  // Comneon

#define USB_VID_ASE 0x0835  // Action Star Enterprise

#define USB_PID_ACC_MIN       0x2D00
#define USB_PID_ACC_MAX       0x2D05
