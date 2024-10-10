#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include <stdint.h>

#define BITS_BEFORE_DP 17 // Number of bits before decimal point
#define BITS_AFTER_DP 14 // Number of bits after decimal point
#define F (1 << BITS_AFTER_DP) // 17.14 fixed-point number representation

/* Convert n to fixed point */
#define INT_TO_FP(n) ((n) * (F))

/* Convert x to integer (rounding toward zero) */
#define FP_TO_INT_FLOOR(x) ((x) / (F))

/* Convert x to integer (rounding to nearest) */
#define FP_TO_INT_ROUND(x) \
    (((x) >= 0) ? (((x) + (F) / 2) / (F)) : (((x) - F / 2) / (F)))

/* Add two fixed-point numbers (x and y) */
#define ADD_FP(x, y) ((x) + (y))

/* Subtract two fixed-point numbers (y from x) */
#define SUB_FP(x, y) ((x) - (y))

/* Add a fixed-point number and an integer (x and n) */
#define ADD_FP_INT(x, n) ((x) + (n) * (F))

/* Subtract an integer from a fixed-point number (n from x) */
#define SUB_FP_INT(x, n) ((x) - (n) * (F))

/* Multiply two fixed-point numbers (x by y) */
#define MUL_FP(x, y) (((int64_t)(x)) * (y) / (F))

/* Multiply a fixed-point number by an integer (x by n) */
#define MUL_FP_INT(x, n) ((x) * (n))

/* Divide two fixed-point numbers (x by y) */
#define DIV_FP(x, y) (((int64_t)(x)) * (F) / (y))

/* Divide a fixed-point number by an integer (x by n) */
#define DIV_FP_INT(x, n) ((x) / (n))

#endif //THREADS_FIXED_POINT_H
