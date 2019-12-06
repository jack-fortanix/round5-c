/*
 * Copyright (c) 2018, Koninklijke Philips N.V.
 */

/**
 * @file
 * Declaration of miscellaneous macros and functions.
 */

#ifndef MISC_H
#define MISC_H

#include <stdlib.h>
#include "types.h"

/** Macro for printing errors. */

    /**
     * Prints the given data as hex digits.
     *
     * @param[in] var          the name of the data variable, printed before the data followed by an `=`,
     *                         can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] data         the data to print
     * @param[in] nr_elements  the number of elements in the data
     * @param[in] element_size the size of the elements in bytes (bytes will be reversed inside element)
     */
    void print_hex(const char *var, const uint8_t *data, const size_t nr_elements, const size_t element_size);

    /**
     * Prints the given vector in a format usable within sage.
     *
     * @param[in] var         the name of the variable, printed before the vector content followed by an `=`,
     *                        can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] vector      the vector
     * @param[in] nr_elements the number of elements of the vector
     */
    void print_sage_u_vector(const char *var, const uint16_t *vector, const size_t nr_elements);

    /**
     * Prints the given scalar matrix in a format usable within sage.
     *
     * @param[in] var        the name of the variable, printed before the matrix content followed by an `=`,
     *                       can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] matrix     the matrix
     * @param[in] nr_rows    the number of rows
     * @param[in] nr_columns the number of columns
     */
    void print_sage_u_matrix(const char *var, const uint16_t *matrix, const size_t nr_rows, const size_t nr_columns);

    /**
     * Prints the given matrix of vectors in a format usable within sage.
     *
     * @param[in] var         the name of the variable, printed before the matrix content followed by an `=`,
     *                        can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] matrix      the matrix
     * @param[in] nr_rows     the number of rows
     * @param[in] nr_columns  the number of columns
     * @param[in] nr_elements the number of elements of the vectors
     */
    void print_sage_u_vector_matrix(const char *var, const uint16_t *matrix, const size_t nr_rows, const size_t nr_columns, const size_t nr_elements);

    /**
     * Prints the given vector in a format usable within sage.
     *
     * @param[in] var         the name of the variable, printed before the vector content followed by an `=`,
     *                        can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] vector      the vector
     * @param[in] nr_elements the number of elements of the vector
     */
    void print_sage_s_vector(const char *var, const int16_t *vector, const size_t nr_elements);

    /**
     * Prints the given scalar matrix in a format usable within sage.
     *
     * @param[in] var        the name of the variable, printed before the matrix content followed by an `=`,
     *                       can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] matrix     the matrix
     * @param[in] nr_rows    the number of rows
     * @param[in] nr_columns the number of columns
     */
    void print_sage_s_matrix(const char *var, const int16_t *matrix, const size_t nr_rows, const size_t nr_columns);

    /**
     * Prints the given matrix of vectors in a format usable within sage.
     *
     * @param[in] var         the name of the variable, printed before the matrix content followed by an `=`,
     *                        can be `NULL` to inhibit printing of `var=` and the final newline
     * @param[in] matrix      the matrix
     * @param[in] nr_rows     the number of rows
     * @param[in] nr_columns  the number of columns
     * @param[in] nr_elements the number of elements of the vectors
     */
    void print_sage_s_vector_matrix(const char *var, const int16_t *matrix, const size_t nr_rows, const size_t nr_columns, const size_t nr_elements);

#endif /* MISC_H */
