// Radix Sort adapted from https://github.com/AwardOfSky/Fast-Radix-Sort
#include "radixsort.h"
#include <string.h>
#include <stdlib.h>
#include <stdexcept>
#define register

template<typename T>
int array_sorted(T vector[], int size);
template<typename T>
void int_radix_sort(register T vector[], register unsigned int size);
#include <algorithm>
#include <stdexcept>
#include <vector>

/* Sanity check for unsorted elements */
template<typename T>
int array_sorted(T vector[], int size) {
    int i, flag = 1;
    for(i = 1; i < size && flag; ++i) {
	if(vector[i] < vector[i - 1]) {
	    flag = 0;
	}
    }
    return flag;
}

/* Core algorithm template:                                              */
/* 1 - Fill the buckets (using byte iterators)                           */
/* 2 - Check if there is 1 bucket w/ all elements (no need to sort byte) */
/* 3 - Set the pointers to the helper array if setting the byte          */
/* 4 - Iterate the bucket values within the orginal array and chnage the */
/*     corresponding values in the helper                                */
#define LAST_EXP__ ((int) sizeof(T) << 3)
template<typename T, bool do_shift, bool do_copy>
void sort_byte(T *vector, T *helper,	int &exp,
		 T **pointer, T **copy, const int &size, int &swap) {
  int shift = exp;
  if(!do_shift){
    shift = 0;
    }
    int bucket[0x100] = {0};
    T *k;
    unsigned char *m, *n = (unsigned char *)(vector) + (exp >> 3);
    for(m = (unsigned char *)(&vector[size & (~0 << 3)]); n < m;) {
	++bucket[*n]; n += sizeof(T);
	++bucket[*n]; n += sizeof(T);
	++bucket[*n]; n += sizeof(T);
	++bucket[*n]; n += sizeof(T);
	++bucket[*n]; n += sizeof(T);
	++bucket[*n]; n += sizeof(T);
	++bucket[*n]; n += sizeof(T);
	++bucket[*n]; n += sizeof(T);
    }
    for(n = (unsigned char *)(&vector[size & (~0 << 3)]) + (exp >> 3),
	    m = (unsigned char *)(&vector[size]); n < m;) {
	++bucket[*n]; n += sizeof(T);
    }
    T *s = helper;
    int next = 0;
    int i;
    if(size > 65535) {
	for(i = 0; i < 0x100 && !next; ++i) {
	    if(bucket[i] == size) {
	        if(do_copy){
		  copy[i] = s;
		  pointer[i] = s + size;
		}else{
		  throw std::runtime_error("optional_ptr_init");
		}
		next = 1;
	    }
	}
    }
    if(!next) {
      if(std::is_unsigned<T>::value || exp != (LAST_EXP__ - 8)) {
	    for(i = 0; i < 0x100; s += bucket[i++]) {
	      pointer[i] = s;
	      if(do_copy){
		copy[i] = s;
	      }
	    }
	} else {
	    for(i = 128; i < 0x100; s += bucket[i++]) {
	      pointer[i] = s;
	      if(do_copy){
		copy[i] = s;
	      }
	    }
	    for(i = 0; i < 128; s += bucket[i++]) {
	      pointer[i] = s;
	      if(do_copy){
		copy[i] = s;
	      }
	    }
	}
      constexpr bool eludeShift = true;
      if(eludeShift){
	unsigned char *n = (unsigned char *)(vector) + (exp >> 3);
	for(s = vector, k = &vector[size & (~0 << 3)]; s < k;) {
	  *pointer[*n]++ = *s;	++s; n += sizeof(T);
	  *pointer[*n]++ = *s;	++s; n += sizeof(T);
	  *pointer[*n]++ = *s;	++s; n += sizeof(T);
	  *pointer[*n]++ = *s;	++s; n += sizeof(T);
	  *pointer[*n]++ = *s;	++s; n += sizeof(T);
	  *pointer[*n]++ = *s;	++s; n += sizeof(T);
	  *pointer[*n]++ = *s;	++s; n += sizeof(T);
	  *pointer[*n]++ = *s;	++s; n += sizeof(T);
	}
	for(s = &vector[size & (~0 << 3)], k = &vector[size]; s < k;) {
	  *pointer[*n]++ = *s;	++s; n += sizeof(T);
	}
      }else{
	for(s = vector, k = &vector[size & (~0 << 3)]; s < k;) {
	    *pointer[(*s >> shift) & 0xFF]++ = *s;	++s;
	    *pointer[(*s >> shift) & 0xFF]++ = *s;	++s;
	    *pointer[(*s >> shift) & 0xFF]++ = *s;	++s;
	    *pointer[(*s >> shift) & 0xFF]++ = *s;	++s;
	    *pointer[(*s >> shift) & 0xFF]++ = *s;	++s;
	    *pointer[(*s >> shift) & 0xFF]++ = *s;	++s;
	    *pointer[(*s >> shift) & 0xFF]++ = *s;	++s;
	    *pointer[(*s >> shift) & 0xFF]++ = *s;	++s;
	}
	for(s = &vector[size & (~0 << 3)], k = &vector[size]; s < k;) {
	    *pointer[(*s >> shift) & 0xFF]++ = *s; ++s;
	}
      }
	swap = 1 - swap;
    }
    exp += 8;
}
template<typename T, bool do_shift, bool do_copy>
void SORT_BYTE__(T *vector, T *helper,	int &exp,
		 T **pointer, T **copy, const int &size, int &swap) {
  return sort_byte<T, do_shift, do_copy>(vector, helper, exp, pointer, copy, size, swap);
  /*switch(exp){
#define CASE(x) case x: sort_byte<T, x, do_copy>(vector, helper, exp, pointer, copy, size, swap); break;
    CASE(0)
    CASE(8)
    CASE(16)
    CASE(24)
    CASE(32)
    CASE(40)
    CASE(48)
    CASE(56)
    CASE(64)
    CASE(72)
    CASE(80)
    CASE(88)
    CASE(96)
    CASE(104)
    CASE(112)
    CASE(120)
#undef CASE
  default:
    throw std::runtime_error("err");
    }
  */
}
/*
  Integer Radix LSD sort. Stable and out-of-place.
  ---Parameters---
  
  vector[] - Pointer to the orginal array of integers
  size     - Size of the array to sort
 
 ---List of optimizations implemented---
  For a list of all optimizations implemented check the github README.md
  over at https://github.com/AwardOfSky/Fast-Radix-Sort
 */
template<typename T>
void int_radix_sort(register T vector[], register unsigned int size) {

    /* Support for variable sized integers without overflow warnings */
#define MAX_UINT__ ((unsigned int)(~0) >> 1)
    /* Define std preliminary, abosulte max value and if there are bytes left */
#define PRELIMINARY__ 64
#define ABS_MAX__ ((max < -exp) ? -exp : max)
#define MISSING_BITS__ exp < LAST_EXP__  && exp < last_exp
    /* Check for max and min integer in [a, b[ array segment */
#define LOOP_MAX__(a, b)				\
    for(s = &vector[a], k = &vector[b]; s < k; ++s) {	\
	if(*s > max || *s < exp) {			\
    	    if(*s > max)  {				\
    		max = *s;				\
    	    } else {					\
    		exp = *s;				\
    	    }						\
    	}						\
    }
    
    register T *helper; /* Helper array */
    int swap = 0; /* Tells where sorted array is (if, sorted is in vector) */
    int last_byte_sorted = 0; /* 1 if we had to sort the last byte */
    unsigned int init_size = size; /* Copy (needed if doing subdivisions) */

    #ifdef dynrange
    register T min = *vector; /* Bits sorted */
    int next = 0;  /* If 1 we skip the byte (all buckets are the same) */
    register T *s, *k, i; /* Array iterators */
    register unsigned char *n, *m; /* Iterator of a byte within an integer */
    /* Preliminary value to retrieve some initial info from the array */
    const int prel = (size > (PRELIMINARY__ << 1)) ? PRELIMINARY__ : (size >> 3);
    
    register T max = min;  /* Maximun range in array */
    /* Get max value (to know how many bytes to sort) */
    LOOP_MAX__(1, prel);
    LOOP_MAX__(size - prel, size);
    if(ABS_MAX__ <= (MAX_UINT__ >> 7) || (max - min == 0)) {
	LOOP_MAX__(prel, size - prel);
    }
    unsigned int diff = max - min;
    max = ABS_MAX__;

    /* Set number of bytes to sort according to max */
    int exp = 0;
    int bytes_to_sort = 0;
    if(diff != 0) {
	bytes_to_sort = 1;
	exp = 8;
	while(exp < LAST_EXP__ && (max >> (exp - 1)) > 0) {
	    bytes_to_sort++;
	    exp += 8;
	}
    } else { /* 1 unique element */
	return;
    }
    #else
    int bytes_to_sort = sizeof(T);
    int exp = sizeof(T) * 8;
    #endif
    
    /* Helper array initialization */
    helper = (T *)malloc(sizeof(T) * size);

    
    T *point[0x100] = {0}; /* Array of pointers to the helper array */

    if(bytes_to_sort > 1 && size*sizeof(T) > 400000) { /* MSB order (size > 1.6M) */

	exp -= 8;

	/* old_point will serve as a copy of the initial values of "point" */
	/* Beggining of each subarray in 1st subdivision (256 subarrays) */
	T *old_point[0x100] = {0};
       
	/* Sort last byte */
	SORT_BYTE__<T, true, true>(vector, helper, exp, point,
				   old_point, size, swap);
	bytes_to_sort--;
	if(exp == LAST_EXP__) {
	    last_byte_sorted = 1;
	}

	/* 2nd subdivision only for 3 bytes or more (and size > 512M) */
	register int j;
	if(bytes_to_sort > 1 && size*sizeof(T) > 64000000) {

	    exp -= 16;
	    
	    /* Same purpose as "point" and old_point" but for 2nd subdivision */
	    T *point_2msb[0x10000] = {0};
	    T *old_point_2msb[0x10000] = {0};
	    int swap_copy = swap; /* Reset value of swap after each subarray */

	    /* Sort second to last byte in LSB order (256 subdivisions) */
	    for(j = 0; j < 0x100; ++j) {
		size = point[j] - old_point[j];
		swap = swap_copy;

		/* Define temporary vector and helper according to current swap*/
		register T *sub_help, *sub_vec;
		if(swap) {
		    sub_vec = old_point[j];
		    sub_help = vector + (old_point[j] - helper);
		} else {
		    sub_vec = vector + (old_point[j] - helper);
		    sub_help = old_point[j];
		}

		/* Temporary for ea subdivision, these work as "array riders" */
		T **point_2msb_rider = point_2msb + (j << 8);
		T **old_point_2msb_rider = old_point_2msb + (j << 8);

		/* Actually sort the byte */
		SORT_BYTE__<T, true, true>(sub_vec, sub_help, exp, point_2msb_rider, old_point_2msb_rider, size, swap);
		exp -= 8;

		/* Make sure the sorted array is in the original vector */
		if(swap) {
		    if(swap_copy) {
			memcpy(sub_help, sub_vec, sizeof(T) * size);
		    } else {
			memcpy(sub_vec, sub_help, sizeof(T) * size);
		    }
		}
			       
	    }
	    swap = 0; /* Because now sorted array is in vector*/
	    bytes_to_sort--;

	    /* Sort remaining bytes in LSB order (65536 subdivisions) */
	    //max = 1 << ((bytes_to_sort - 1) << 3);
	    int last_exp = bytes_to_sort * 8;
	    for(j = 0; j < 0x10000; ++j) {

		exp = 0;
		size = point_2msb[j] - old_point_2msb[j];
		swap = 0; /* Reset swap (last swap is always 0) */

		/* Define temp arrays according to wether the first MSB byte */
		/* was sorted or not (array pointed by old_point_2msb changes) */
		register T *sub_help, *sub_vec;
		if(swap_copy) {
		    sub_vec = old_point_2msb[j];
		    sub_help = helper + (old_point_2msb[j] - vector);
		} else {
		    sub_vec = vector + (old_point_2msb[j] - helper);
		    sub_help = old_point_2msb[j];
		}

		while(MISSING_BITS__) { /* While there are remaining bytes */
		    if(exp) {
			if(swap) {
			  SORT_BYTE__<T, true, false>(sub_help, sub_vec, exp, point, nullptr, size, swap);
			} else { /* Note: won't happen in 32 bit integers */
			  SORT_BYTE__<T, true, false>(sub_vec, sub_help, exp, point, nullptr, size, swap);
			}
		    } else {
		      SORT_BYTE__<T, false, false>(sub_vec, sub_help, exp,
				    point, nullptr, size, swap);
		    }
		}

		if(swap) { /* Force sorted segments to be in original vector */
		    memcpy(sub_vec, sub_help, sizeof(T) * size);
		}

	    }
	    swap = 0;

	} else {

	    /* Start sorting from LSB now */
	    //max = 1 << ((bytes_to_sort) << 3);
 	    int last_exp = bytes_to_sort * 8;
	    int swap_copy = swap; /* Once more, reset swap in ea subarray */
	    for(j = 0; j < 0x100; ++j) {
	    	exp = 0;
	    	size = point[j] - old_point[j];
	    	swap = swap_copy;

		register T *sub_help, *sub_vec; /* Temprary arrays */
		if(swap) {
		    sub_help = vector + (old_point[j] - helper);
		    sub_vec = old_point[j];
		} else {
		    sub_help = old_point[j];
		    sub_vec = vector + (old_point[j] - helper);
		}

		T *temp_point[0x100]; /* Temp ptrs, just to sort this segment */
		while(MISSING_BITS__) { /* While there are remaining bytes */
		    if(exp) {
			if(swap != swap_copy) {
			  SORT_BYTE__<T, true, false>(sub_help, sub_vec, exp,
					temp_point, nullptr, size, swap);
			} else {
			  SORT_BYTE__<T, true, false>(sub_vec, sub_help, exp,
					temp_point, nullptr, size, swap);
			}
		    } else {
		      SORT_BYTE__<T, false, false>(sub_vec, sub_help, exp,
					       temp_point, nullptr, size, swap);
		    }
		}

		if(swap) { /* Again, make sure sorted array is the vector */
		    if(swap_copy) {
			memcpy(sub_help, sub_vec, sizeof(T) * size);
		    } else {
			memcpy(sub_vec, sub_help, sizeof(T) * size);
		    }
		}
	    }
	    swap = 0;
	}
   
    } else if(bytes_to_sort > 0) { /* Use normal LSB radix (no subarrays) */

	exp = 0; /* Start at the first byte */

	//max = T{1} << ((bytes_to_sort) << 3);
	int last_exp = bytes_to_sort * 8;
	while(MISSING_BITS__) { /* Sort until there are no bytes left */
	    if(exp) {
		if(swap) {
		  SORT_BYTE__<T, true, false>(helper, vector, exp,
				point, nullptr, size, swap);
		} else {
		  SORT_BYTE__<T, true, false>(vector, helper, exp,
				point, nullptr, size, swap);
		}
	    } else {
	      SORT_BYTE__<T, false, false>(vector, helper, exp,
				       point,nullptr, size, swap);
	    }

	    if(exp == LAST_EXP__) { /* Check if last byte was sorted */
	    	last_byte_sorted = 1;
	    }
	}

    }
    
    /* Find the first negative element in the array in binsearch style */
#define BINSEARCH__(array)						\
    int increment = size >> 1;						\
    int offset = increment;						\
    while((array[offset] ^ array[offset - 1]) >= 0) {			\
	increment = (increment > 1) ? increment >> 1 : 1;		\
	offset = (array[offset] < 0) ? offset - increment : offset + increment; \
    }
    
    size = init_size; /* Restore size */
    T *v = vector;  /* Temporary values for the vfector and helper arrays */
    T *h = helper;
    /* In case the array has both negative and positive integers, find the    */
    /* index of the first negative integer and put those numbers in the start */
    if(std::is_unsigned<T>::value && !last_byte_sorted && (((*v ^ v[size - 1]) < 0 && !swap) ||
			     ((*h ^ h[size - 1]) < 0 && swap))) {
	/* If sorted array is in vector, use helper to re-order and vs */
      throw std::runtime_error("here");
    	if(!swap)  {
	    BINSEARCH__(v);

    	    int tminusoff = size - offset;
    	    if(offset < tminusoff) {
    	    	memcpy(h, v, sizeof(int) * offset);
    	    	memcpy(v, v + offset, sizeof(int) * tminusoff);
    	    	memcpy(v + tminusoff, h, sizeof(int) * offset);
    	    } else {
    	    	memcpy(h, v + offset, sizeof(int) * tminusoff);
    	    	memmove(v + tminusoff, v, sizeof(int) * offset);
    	    	memcpy(v, h, sizeof(int) * tminusoff);
    	    }
	} else {
	    BINSEARCH__(h);

    	    int tminusoff = size - offset;
    	    memcpy(v, h + offset, sizeof(int) * tminusoff);
    	    memcpy(v + tminusoff, h, sizeof(int) * (size - tminusoff));
    	}
    } else if(swap) {
    	memcpy(v, h, sizeof(T) * size);
    }

    /* Free helper array */
    free(helper);

}

template<typename T>
static int check(T vector[], int size) {
    int i, flag = 1;
    for(i = 1; i < size && flag; ++i) {
	if(vector[i] < vector[i - 1]) {
	    flag = 0;
	}
    }
    if(flag == 0){
      throw std::runtime_error("unsorted");
    }
}

template<typename T>
void radix_sort(std::vector<T> &data){
  int_radix_sort(data.data(), data.size());
  //check(data.data(), data.size());
}
template
void radix_sort<uint64_t>(std::vector<uint64_t> &data);


template<typename T>
void radix_sort(T *data, size_t size){
  int_radix_sort(reinterpret_cast<__int128*>(data), size);
  //check(reinterpret_cast<__int128*>(data), size);
}
template
void radix_sort<unsigned __int128>(unsigned __int128 *data, size_t size);


template<typename T>
static void test(unsigned int size){
    /* Initial variable declaration */
    srand(time(NULL));
    clock_t t;
    int i;

    /* Check for inconsistensies and constrains */
    if(size < 0) {
	size = -size;
    }

    /* Allocate and randomly shuffle the array */
    auto a = std::vector<T>(size);
    {
      char *bytes = reinterpret_cast<char*>(a.data());
      int bytes_size = sizeof(T) * size;
      for(i = 0; i < bytes_size; ++i) {
	bytes[i] = (char) rand();
      }
    }
        
    /* Time sort function execution */
    t = clock();
    int_radix_sort(a.data(), size);
    t = clock() - t;
    double time = (double)t / CLOCKS_PER_SEC;
  
    /* Print results */
    printf("\nRadix sort took %f seconds.\n[sorted %d %ld-bit numbers].\n",
	   time, size, sizeof(T)*8);

    if(array_sorted(a.data(), size) != 0){
	printf("The array was sorted successfully!\n");
    } else {
    	printf("The array wasn't fully sorted. Please report this problem!\n");
    }
}

/*int main(int argc, char * argv []) {

  //test<int>(20'000'000);
  //test<unsigned int>(20'000'000);
  //test<uint64_t>(20'000'000);
    test<unsigned __int128>(20'000'000);

    return 0;
}
*/
