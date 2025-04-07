#pragma once
#include <vector>
#include <stdint.h>
#include <stddef.h>


template<typename T>
void radix_sort(std::vector<T> &data);

template<typename T>
void radix_sort(T *data, size_t size);
