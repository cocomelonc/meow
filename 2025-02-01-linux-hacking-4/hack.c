/*
 * hack.c
 * measuring cache hit and cache miss times
 * author @cocomelonc
 * https://cocomelonc.github.io/linux/2025/02/01/linux-hacking-4.html
 */
#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define ARRAY_SIZE (1024 * 1024)  // 1 MB array

uint8_t array[ARRAY_SIZE];

uint64_t measure_access_time(volatile uint8_t *address) {
  uint64_t start, end;
  unsigned int aux;  // auxiliary variable for __rdtscp
  
  _mm_mfence();  // memory fence to prevent instruction reordering
  start = __rdtscp(&aux);  // start timing
  (void)*address;      // access memory
  _mm_mfence();  // memory fence to prevent instruction reordering
  end = __rdtscp(&aux);  // end timing

  return end - start;
}

void flush_cache() {
  // flush the cache by accessing a large amount of data
  uint8_t *dummy = (uint8_t *)malloc(ARRAY_SIZE);
  for (int i = 0; i < ARRAY_SIZE; i++) {
    dummy[i] = i;
  }
  free(dummy);
}

int main() {
  uint64_t cached_time, uncached_time;

  // access an element that is already in the cache (CACHE HIT)
  volatile uint8_t *cached_addr = &array[0];
  *cached_addr = 42;  // load into cache
  cached_time = measure_access_time(cached_addr);
  
  // flush the cache and access a different element (CACHE MISS)
  flush_cache();
  volatile uint8_t *uncached_addr = &array[ARRAY_SIZE/2];  
  uncached_time = measure_access_time(uncached_addr);

  printf("cache hit time: %lu cycles\n", cached_time);
  printf("cache miss time: %lu cycles\n", uncached_time);

  return 0;
}