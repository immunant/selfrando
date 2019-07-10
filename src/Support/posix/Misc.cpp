/*
 * This file is part of selfrando.
 * Copyright (c) 2015-2019 RunSafe Security Inc.
 * For license information, see the LICENSE file
 * included with selfrando.
 *
 */

#include "Misc.h"
#include <cstdio>
#include <cstdlib>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>


bool Misc::exec_child(char *args[], int *status, bool quiet) {
    int pid = fork();
    if (pid == 0) {
        // Child process

        // If quiet, redirect stdout and stderr to /dev/null
        if (quiet) {
            int null_fd = open("/dev/null", O_WRONLY);
            if (null_fd < 0)
                exit(-1);
            dup2(null_fd, 1);
            dup2(null_fd, 2);
            close(null_fd);
        }

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
        int wait_status = 0;
        if (waitpid(pid, &wait_status, 0) == -1)
            return false;

        if (status != nullptr)
            *status = WEXITSTATUS(wait_status);
        return true;
    }
}
