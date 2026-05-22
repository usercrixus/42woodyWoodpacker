#pragma once

#include "woody.h"

struct xtea_ctr_data
{
    uint64_t nonce;
    uint32_t key[4];
};

int xtea_ctr_encrypt(uint8_t *data, size_t len, uint8_t algo_data[ALGO_DATA_SIZE]);
void xtea_ctr_decrypt(uint8_t *cursor, uint64_t remaining, const uint8_t algo_data[ALGO_DATA_SIZE]);
