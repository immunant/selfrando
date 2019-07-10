#!/usr/bin/env python2.7
# Copyright (c) 2015-2019 RunSafe Security Inc.

import os
import sys
import psutil
import tempfile

IGNORED_ENV_VARS = [
    'USER',
    'SHELL',
    # 'PATH',
    'HOME',
    # 'PWD',
    '_',
    'LS_COLORS',
    'CLUTTER_IM_MODULE',
    'COMPIZ_BIN_PATH',
    'COMPIZ_CONFIG_PROFILE',
    'COLORTERM',
    'DBUS_SESSION_BUS_ADDRESS',
    'DEFAULTS_PATH',
    'DESKTOP_SESSION',
    'DISPLAY',
    'GDMSESSION',
    'GDM_LANG',
    'GNOME_DESKTOP_SESSION_ID',
    'GNOME_SESSION_XDG_SESSION_PATH',
    'GTK2_MODULES',
    'GTK_IM_MODULE',
    'GTK_MODULES',
    'IM_CONFIG_PHASE',
    'JOURNAL_STREAM',
    'LANG',
    'LANGUAGE',
    'LESSCLOSE',
    'LESSOPEN',
    'LOGNAME',
    'MAIL',
    'MANAGERPID',
    'MANDATORY_PATH',
    'OLDPWD',
    'SESSION_MANAGER',
    'SSH_AGENT_LAUNCHER',
    'SSH_AUTH_SOCK',
    'SSH_TTY',
    'SSH_CLIENT',
    'SSH_CONNECTION',
    'SHLVL',
    'TERM',
    'QT4_IM_MODULE',
    'QT_ACCESSIBILITY',
    'QT_IM_MODULE',
    'QT_LINUX_ACCESSIBILITY_ALWAYS_ON',
    'QT_QPA_PLATFORMTHEME',
    'UPSTART_SESSION',
    'VTE_VERSION',
    'WINDOWID',
    'XAUTHORITY',
    'XDG_CONFIG_DIRS',
    'XDG_CURRENT_DESKTOP',
    'XDG_DATA_DIRS',
    'XDG_GREETER_DATA_DIR',
    'XDG_MENU_PREFIX',
    'XDG_RUNTIME_DIR',
    'XDG_SEAT_PATH',
    'XDG_SESSION_DESKTOP',
    'XDG_SESSION_ID',
    'XDG_SESSION_PATH',
    'XDG_SESSION_TYPE',
    'XMODIFIERS',
    'ZEITGEIST_DATA_PATH',
]


def dump_env(fh, environ):
    for key, val in environ.items():
        if key in IGNORED_ENV_VARS:
            continue
        # print key + ":" + val
        fh.write("{}:{}\n".format(key, val))


def dump_proc(fh, proc):
    dump_env(fh, proc.environ())

    for i, arg in enumerate(proc.cmdline()):
        # print "{}:{}".format(i, arg)
        fh.write("arg{}:{}\n".format(i, arg))

    try:
        pproc = proc.parent()
        if pproc and proc.username() == pproc.username():
            fh.write("# dumping parent process %d\n" % proc.ppid())
            dump_proc(fh, pproc)
    except psutil.AccessDenied:
        fh.write("# access to parent process %d denied\n" % proc.ppid())

tempfile.tempdir = "/tmp"
ROOT_PROC = psutil.Process(os.getpid()) # .parent()
with tempfile.NamedTemporaryFile(delete=False, prefix='argtrace') as fh:
    dump_proc(fh, ROOT_PROC)
    print fh.name
