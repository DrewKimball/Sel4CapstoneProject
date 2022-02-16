/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <camkes.h>
#include <stdio.h>
#include <stdlib.h>

int run(void) {
  char* buf = (char*)malloc(20);
  sprintf(buf, "Hello World!\n");
  printf("%s", buf);
  free(buf);
  return 0;
}
