
#pragma once
#include <stdio.h>
#include <stdlib.h>

#define _TEST_LOG_FMT(status, status_color, form, fmt, ...)\
printf("\e[" #status_color "m[" status "]\e[m %s:%d %s " fmt "\n", __FILE__, __LINE__, #form __VA_OPT__(,) __VA_ARGS__)

#define _TEST_LOG(status, status_color, form)\
printf("\e[" #status_color "m[" status "]\e[m %s:%d %s\n", __FILE__, __LINE__, #form)

#define TEST(form, ...)\
if (form){\
_TEST_LOG ## __VA_OPT__(_FMT)("success", 32, form __VA_OPT__(,) __VA_ARGS__);\
}\
else {\
_TEST_LOG ## __VA_OPT__(_FMT)("fail", 31, form __VA_OPT__(,) __VA_ARGS__);\
abort();\
}
