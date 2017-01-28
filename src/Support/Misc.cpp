/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2017 Immunant Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include "Misc.h"
#include <cstdio>
#include <cstdlib>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


bool Misc::exec_child(char *args[], int *status) {
    int pid = fork();
    if (pid == 0) {
        // Child process

        execvp(args[0], args);
        // If execvp failed, terminate this child
        // FIXME: we need a better way to signal to the parent
        // that execvp failed
        exit(-1);
    } else {
        // Parent process

        if (pid == -1)
            return false;

        // Wait for child to finish
        if (waitpid(pid, status, 0) == -1)
            return false;

        return true;
    }
}
