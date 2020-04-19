#pragma once

#define PRINT_STAT_LINE(description, counter, measurement, type) \
    printf("%-46s %14" type " [%s]\n", description ":", counter, measurement)

#define PRINT_STAT_LINE_INT(description, counter, measurement) \
    PRINT_STAT_LINE(description, counter, measurement, "d")

#define PRINT_STAT_LINE_DOUBLE(description, counter, measurement) \
    PRINT_STAT_LINE(description, counter, measurement, ".3f")

#define PRINT_STAT_HEADLINE(description) \
    printf("\n" description "\n--------------------\n\n")
