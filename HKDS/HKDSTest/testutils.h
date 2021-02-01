#ifndef HKDSTEST_TESTUTILS_H
#define HKDSTEST_TESTUTILS_H

#include "common.h"

/**
* \brief Get a single character from the console
* 
* \return Returns the character detected
*/
char hkdstest_get_char();

/**
* \brief Pause the console until user input is detected
*/
void hkdstest_get_wait();

/**
* \brief Convert a hexadecimal character string to a binary byte array
*
* \param hexstr: the string to convert
* \param output: the binary output array
* \param length: the number of bytes to convert
*/
void hkdstest_hex_to_bin(const char* hexstr, uint8_t* output, size_t length);

/**
* \brief Convert a binary array to a hexidecimal string and print to the console
*
* \param input: the binary array
* \param inputlen: the number of bytes to process
* \param linelen: the length of output to print, before starting a new line
*/
void hkdstest_print_hex(const uint8_t* input, size_t inputlen, size_t linelen);

/**
* \brief Print an array of characters to the console
*
* \param input: the character array to print
*/
void hkdstest_print_safe(const char* input);

/**
* \brief Print an array of characters to the console with a line break
*
* \param input: the character array to print
*/
void hkdstest_print_line(const char* input);

/**
* \brief Print an unsigned 64-bit integer
*
* \param digit: the number to print
*/
void hkdstest_print_ulong(uint64_t digit);

/**
* \brief Print a double integer
*
* \param digit: the number to print
*/
void hkdstest_print_double(double digit);

/**
* \brief User confirmation that and action can continue(Y/N y/n)
*
* \param message: the message to print
*/
bool hkdstest_test_confirm(char* message);

#endif
