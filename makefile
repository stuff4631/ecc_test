#####################################################################
## file        : test makefile for build current dir .c   ##
## author      : lvyanpeng                                ##
## date-time   : 21/12/2017                               ##
#####################################################################

CC      = gcc
CPP     = g++
RM      = rm -rf

## debug flag
DBG_ENABLE   = 0

## source file path
SRC_PATH   := .

## target exec file name
TARGET     := ecdsa_sign_tool

## get all source files
SRCS         += $(wildcard $(SRC_PATH)/*.c)

## all .o based on all .c
OBJS        := $(SRCS:.c=.o)


## need libs, add at here
LIBS := ssl crypto

## used headers  file path
##INCLUDE_PATH := /home/linux/opt/openssl/include/
INCLUDE_PATH := /usr/local/include/openssl/

## used include librarys file path
##LIBRARY_PATH := /home/linux/opt/openssl/lib/
LIBRARY_PATH := /usr/local/lib/

## debug for debug info, when use gdb to debug
ifeq (1, ${DBG_ENABLE}) 
	CFLAGS += -D_DEBUG -O0 -g -DDEBUG=1
endif

## get all include path
CFLAGS  += $(foreach dir, $(INCLUDE_PATH), -I$(dir))

## get all library path
LDFLAGS += $(foreach lib, $(LIBRARY_PATH), -L$(lib))

## get all librarys
LDFLAGS += $(foreach lib, $(LIBS), -l$(lib))


all: clean build

build:
	$(CC) -c $(CFLAGS) $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)
	$(RM) $(OBJS)

clean:
	$(RM) $(OBJS) $(TARGET)
