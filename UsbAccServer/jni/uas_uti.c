#include "uas_uti.h"

#define LOG_FILE

#ifndef NDEBUG
char * state_get (int state) {
  switch (state) {
    case uas_STATE_INITIAL:                                           // 0
      return ("uas_STATE_INITIAL");
    case uas_STATE_STARTIN:                                           // 1
      return ("uas_STATE_STARTIN");
    case uas_STATE_STARTED:                                           // 2
      return ("uas_STATE_STARTED");
    case uas_STATE_STOPPIN:                                           // 3
      return ("uas_STATE_STOPPIN");
    case uas_STATE_STOPPED:                                           // 4
      return ("uas_STATE_STOPPED");
  }
  return ("uas_STATE Unknown error");
}
#endif

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

int gen_server_loop_func (unsigned char * cmd_buf, int cmd_len, unsigned char * res_buf, int res_max);
int gen_server_poll_func (int poll_ms);

int ena_log_send  = 1;
int ena_log_extra = 1;
int ena_log_verbo = 1;
int ena_log_debug = 1;
int ena_log_warni = 1;
int ena_log_error = 1;

int ena_log_hexdu = 0;
int max_hex_dump  = 64;

#ifdef  LOG_FILE
int logfd = -1;
void logfile (char * log_line) {
  if (logfd < 0)
    logfd = open ("/sdcard/aalog", O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
  int written = -77;
  if (logfd >= 0)
    written = write (logfd, log_line, strlen (log_line));
}
#endif

int uas_log (int prio, const char * tag, const char * func, const char * fmt, ...) {

  if (! ena_log_extra && prio == uas_LOG_EXT)
    return -1;
  if (! ena_log_verbo && prio == uas_LOG_VER)
    return -1;
  if (! ena_log_debug && prio == uas_LOG_DEB)
    return -1;
  if (! ena_log_warni && prio == uas_LOG_WAR)
    return -1;
  if (! ena_log_error && prio == uas_LOG_ERR)
    return -1;

  char tag_str [DEFBUF] = {0};
  snprintf (tag_str, sizeof (tag_str), "%32.32s", func);

  va_list ap;
  va_start (ap, fmt); 
#ifdef __ANDROID_API__
  __android_log_vprint (prio, tag_str, fmt, ap);
#else
  char log_line [4096] = {0};
  va_list aq;
  va_start (aq, fmt); 
  int len = vsnprintf (log_line, sizeof (log_line), fmt, aq);
  time_t timet = time (NULL);
  const time_t * timep = & timet;
  char asc_time [DEFBUF] = "";
  ctime_r (timep, asc_time);
  int len_time = strlen (asc_time);
  asc_time [len_time - 1] = 0;        // Remove trailing \n
  printf ("%s %s: %s:: %s\n", & asc_time [11], prio_get (prio), tag, log_line);
#endif

#ifdef  LOG_FILE
  char log_line [4096] = {0};
  va_list aq;
  va_start (aq, fmt); 
  int len = vsnprintf (log_line, sizeof (log_line), fmt, aq);
  strlcat (log_line, "\n", sizeof (log_line));
  logfile (log_line);
#endif
  return (0);
}

unsigned long ms_get () {
  struct timespec tspec = {0, 0};
  int res = clock_gettime(CLOCK_MONOTONIC, &tspec);

  unsigned long millisecs = (tspec.tv_nsec / 1000000L);
  millisecs += (tspec.tv_sec * 1000L);

  return (millisecs);
}

unsigned long ms_sleep(unsigned long ms) {
  struct timespec tm;
  tm.tv_sec = 0;
  tm.tv_sec = ms / 1000L;
  tm.tv_nsec = (ms % 1000L) *  1000000L;
  unsigned long ms_end = ms_get() + ms;
  unsigned long ctr = 0;
  while (ms_get() < ms_end) {
    usleep (32000L);
    ctr ++;
    if (ctr > 25){
      ctr = 0L;
    }
  }
  return (ms);
}


