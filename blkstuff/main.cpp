#include <iostream>
#include <cstdint>
#include <cstring>

#include <random>
#include <filesystem>

#include <lz4.h>

#include "util.h"
#include "magic_constants.h"

using std::cout, std::endl, std::hex, std::dec;

// notes are from the genshin impact 1.5 dev build leak UnityEngine.dll (sha256 38399169552791bbfb7b3792dd3e91d3788067e29ffc2437f595060b051d2dd3)

void key_scramble1(uint8_t* key) {
    // UnityPlayer:$1615F0
    for (unsigned i = 0; i < 0x10; i++)
        key[i] = key_scramble_table1[((i & 3) << 8) | key[i]];
}

uint8_t xor_combine(uint8_t* input) {
    // xors an array of 16 bytes into a single byte
    //hexdump(input, 0x10);
    uint8_t ret = 0;
    for (int i = 0; i < 16; i++)
        ret ^= input[i];
    return ret;
}

void create_decrypt_vector(uint8_t* key, uint8_t* encrypted_data, uint64_t encrypted_size, uint8_t* output, uint64_t output_size) {
    if (output_size != 4096) {
        cout << "create_decrypt_vector does not support an output_size other than 4096" << endl;
        exit(1);
    }

    // TODO: reimplement this properly instead of copy and pasting from decomp
    int v9 = 0;
    int64_t i;
    int64_t v12;
    for (i = -1; ; i = v12) {
        if (v9 >= (int)(encrypted_size >> 3))
            break;
        v12 = ((uint64_t*)encrypted_data)[v9] ^ i;
        ++v9;
    }

    auto* key_qword = (uint64_t*)key;
    // another magic constant, this time from blk_stuff2
    uint64_t seed = key_qword[1] ^ 0x567BA22BABB08098 ^ i ^ key_qword[0];
    //cout << "seed: 0x" << hex << seed << endl;

    auto mt_rand = std::mt19937_64(seed);
    for (uint64_t i = 0; i < output_size >> 3; i++)
        ((uint64_t*)output)[i] = mt_rand();
}

void key_scramble2(uint8_t* key) {
    // UnityPlayer:$26EA90
    uint8_t expanded_key[256] = {};

    // usually this table gets xor'd against random data that's unique for every run
    // obviously if the random data actually mattered, it would make decryption impossible
    for (int i = 0; i < 16; i++)
        expanded_key[i * 16] = key[i];
    for (int i = 0; i < sizeof(expanded_key); i++)
        expanded_key[i] ^= blk_stuff1_p1[i] ^ stack_stuff[i];

    // should probably be in magic_constants.h, but it's very small
    const uint8_t index_scramble[16] = {
        0,  13, 10, 7,
        4,  1,  14, 11,
        8,  5,  2,  15,
        12, 9,  6,  3
    };
    for (uint64_t i = 1; i < 10; i++) {
        uint32_t scratch[4] = {};
        for (uint64_t j = 0; j < 4; j++) {
            uint8_t temp = 0;
            temp = xor_combine(&expanded_key[16 * index_scramble[4 * j]]);
            scratch[j] ^= ((uint32_t*)blk_stuff1_p2)[temp];
            temp = xor_combine(&expanded_key[16 * index_scramble[4 * j + 1]]);
            scratch[j] ^= ((uint32_t*)blk_stuff1_p3)[temp];
            temp = xor_combine(&expanded_key[16 * index_scramble[4 * j + 2]]);
            scratch[j] ^= ((uint32_t*)blk_stuff1_p4)[temp];
            temp = xor_combine(&expanded_key[16 * index_scramble[4 * j + 3]]);
            scratch[j] ^= ((uint32_t*)blk_stuff1_p5)[temp];
        }
        // also usually xor'd
        memset(expanded_key, 0, sizeof(expanded_key));
        for (uint64_t j = 0; j < 16; j++)
            expanded_key[j * 16] = ((uint8_t*)scratch)[j];
        for (uint64_t j = 0; j < 256; j++) {
            uint64_t v10 = j + (i << 8);
            expanded_key[j] ^= blk_stuff1_p1[v10] ^ stack_stuff[v10];
        }
    }
    
    uint8_t scratch[16] = {};
    for (int i = 0; i < 16; i++) {
        uint8_t t = xor_combine(&expanded_key[16 * index_scramble[i]]);
        scratch[i] = blk_stuff1_p6[t] ^ ~t;
    }
    // yes, also usually xor'd
    memset(expanded_key, 0, sizeof(expanded_key));
    for (uint64_t i = 0; i < 16; i++)
        expanded_key[i * 16] = scratch[i];
    for (int i = 0; i < sizeof(expanded_key); i++)
        expanded_key[i] ^= blk_stuff1_p7[i] ^ stack_stuff[i + 0xA00];

    for (int i = 0; i < 16; i++)
        key[i] = xor_combine(&expanded_key[16 * i]);
}

void mhy0_header_scramble2(uint8_t* input)
{
    // UnityPlayer:$152300
    // TODO: more cleanup
    uint8_t* ptr; // rsi
    uint8_t tmp[16];

    uint8_t mhy0_index_scramble[] = {
        0x0B,0x02,0x08,0x0C,0x01,0x05,0x00,0x0F,0x06,0x07,0x09,0x03,0x0D,0x04,0x0E,0x0A,
        0x04,0x05,0x07,0x0A,0x02,0x0F,0x0B,0x08,0x0E,0x0D,0x09,0x06,0x0C,0x03,0x00,0x01,
        0x08,0x00,0x0C,0x06,0x04,0x0B,0x07,0x09,0x05,0x03,0x0F,0x01,0x0D,0x0A,0x02,0x0E,
    };

    uint8_t smol_key[] = {
        0x48, 0x14, 0x36, 0xED, 0x8E, 0x44, 0x5B, 0xB6
    };

    uint8_t v25[] = {
        0xA7, 0x99, 0x66, 0x50, 0xB9, 0x2D, 0xF0, 0x78
    };

    for (int k = 0; k < 3; k++)
    {
        for (int i = 0; i < 16; ++i)
            tmp[i] = input[mhy0_index_scramble[(2 - k)*16 + i]];

        memcpy(input, tmp, 16);

        for (int j = 0; j < 16; ++j)
        {
            ptr = &input[j];
            int idx = j % 8;

            *ptr = smol_key[idx] ^ key_scramble_table1[j % 4 * 256 | gf256_mul(v25[idx], *ptr)];
        }
    }
}

void mhy0_header_scramble(uint8_t* input, uint64_t limit, uint8_t* input2, uint64_t chunk_size) {
    if (!((limit == 0x39 && chunk_size == 0x1C) || (limit == 0x21 && chunk_size == 8))) {
        cout << "unsupported parameters for mhy0_header_scramble" << endl;
        exit(1);
    }

    // UnityPlayer:$151090
    // TODO: reimplement this properly instead of copy and pasting from decomp
    int rounded_size = (chunk_size + 15) & 0xFFFFFFF0;

    for (int i = 0; i < rounded_size; i += 16)
        mhy0_header_scramble2(&input[i + 4]);

    for (int j = 0; j < 4; j++)
        input[j] ^= input2[j];

    uint64_t total_rounded_size = (uint64_t)rounded_size + 4;

    bool finished = false;
    while (total_rounded_size < limit && !finished)
    {
        for (int k = 0; k < chunk_size; ++k)
        {
            input[k + total_rounded_size] ^= input2[k];
            if (k + total_rounded_size >= limit - 1)
            {
                finished = true;
                break;
            }
        }
        total_rounded_size += chunk_size;
    }
}

void mhy0_extract(const char* out_format, int block_index, uint8_t* input, size_t input_size) {
    // loosely based on UnityPlayer:$1C64C0
    // TODO: bounds checks
    if (*(uint32_t*)input != 0x3079686D) { // mhy0
        cout << "decrypted data didn't start with mhy0, so decryption probably failed" << endl;
        exit(1);
    }

    uint32_t size = *(uint32_t*)(input + 4);
    //cout << "first size 0x" << std::hex << size << endl;

    if (size > input_size) {
        // TODO: this is probably caused by the awful mhy0 searching approach i do instead of properly calculating offsets
        cout << "oh shit! attempted to get 0x" << hex << size << " bytes out of a 0x" << hex << input_size << " input! skipping mhy0 " << dec << block_index << endl;
        return;
    }

    auto* data = new uint8_t[size];
    memcpy(data, input + 8, size);

    //hexdump("initial data", data, size);

    mhy0_header_scramble(data, 0x39, data + 4, 0x1C);

    //hexdump("data after scramble", data, size);

    //dump_to_file("output.bin", data, size);

    // TODO: there is a different path for calculating this, so this might mess up on some inputs
    //uint32_t decomp_size = MAKE_UINT32(data[0x20 + 1], data[0x20 + 6], data[0x20 + 3], data[0x20 + 2]);
    uint32_t decomp_size = MAKE_UINT32(data, 0x20 + 1, 0x20 + 6, 0x20 + 3, 0x20 + 2);
    //cout << "decompressed size: 0x" << hex << decomp_size << endl;
    uint8_t* decomp_output = new uint8_t[decomp_size];
    auto lz4_res = LZ4_decompress_safe((const char*)(data + 0x27), (char*)decomp_output, size - 0x27, decomp_size);
    if (lz4_res < 0) {
        cout << "decompression failed: " << lz4_res << endl;
        exit(1);
    }
    delete[] data;
    //dump_to_file("mhy0_header.bin", decomp_output, decomp_size);

    //cout << "next data cmp size: 0x" << hex << MAKE_UINT32(decomp_output, 0x11F + 2, 0x11F + 4, 0x11F, 0x11F + 5) << endl;
    //cout << "next data decmp size: 0x" << hex << MAKE_UINT32(decomp_output, 0x112 + 1, 0x112 + 6, 0x112 + 3, 0x112 + 2) << endl;
    //cout << "unknown 1: 0x" << hex << MAKE_UINT32(decomp_output, 0x10C + 2, 0x10C + 4, 0x10C, 0x10C + 5) << endl;
    auto cab_count = MAKE_UINT32(decomp_output, 2, 4, 0, 5);
    //cout << "cab count: 0x" << hex << cab_count << endl;
    //auto entry_count = MAKE_UINT32(decomp_output, 0x119 + 2, 0x119 + 4, 0x119, 0x119 + 5);
    auto entry_count = MAKE_UINT32(decomp_output, cab_count * 0x113 + 6 + 2, cab_count * 0x113 + 6 + 4, cab_count * 0x113 + 6, cab_count * 0x113 + 6 + 5);
    //cout << "entry count: 0x" << hex << entry_count << endl;
    //dump_to_file("bruh.bin", decomp_output, decomp_size);
    //hexdump("asdf", decomp_output, decomp_size);
    //exit(1);
    //if (entry_count > 0x10000) {
        //hexdump("wtf???? something probably went wrong!", decomp_output, decomp_size);
        //cout << "0x" << hex << MAKE_UINT32(decomp_output, 2, 4, 0, 5) << endl;
        //exit(1);
    //}

    uint8_t* entry_ptr = input + 0x8 + size;
    char filename[0x100] = {};
    //cout << out_format << endl;
    snprintf(filename, sizeof(filename), out_format, block_index);
    auto* output = fopen(filename, "wb");
    if (!output) {
        cout << "failed to open " << filename << endl;
        exit(1);
    }
    for (int i = 0; i < entry_count; i++) {
        //cout << "processing entry " << i << endl;
        auto offset = i * 13 + cab_count * 0x113 + 6;
        auto entry_cmp_size = MAKE_UINT32(decomp_output, offset + 6 + 2, offset + 6 + 4, offset + 6, offset + 6 + 5);
        auto entry_decmp_size = MAKE_UINT32(decomp_output, offset + 0xC + 1, offset + 0xC + 6, offset + 0xC + 3, offset + 0xC + 2);
        //cout << hex << entry_cmp_size << endl;
        //hexdump("initial data", entry_ptr, entry_cmp_size);
        mhy0_header_scramble(entry_ptr, 0x21, entry_ptr + 4, 8);
        //hexdump("data after scramble", entry_ptr, entry_cmp_size);

        auto* entry_decmp = new uint8_t[entry_decmp_size];
        auto lz4_res = LZ4_decompress_safe((const char*)(entry_ptr + 0xC), (char*)entry_decmp, entry_cmp_size - 0xC, entry_decmp_size);
        if (lz4_res < 0) {
            cout << "decompression failed: " << lz4_res << endl;
            exit(1);
        }
        //dump_to_file(filename, entry_decmp, entry_decmp_size);
        fwrite(entry_decmp, entry_decmp_size, 1, output);
        delete[] entry_decmp;
        entry_ptr += entry_cmp_size;
    }
    fclose(output);

    delete[] decomp_output;
}

int extract_blk(char* in_filename, const char* out_format) {
    //auto* blk_file = fopen("D:\\genshinimpactre\\1.5-dev\\YuanShen_Data\\StreamingAssets\\20527480.blk", "rb");
    //auto* blk_file = fopen("D:\\Games\\Genshin Impact\\Genshin Impact game\\GenshinImpact_Data\\StreamingAssets\\VideoAssets\\26236578.blk", "rb");
    auto* blk_file = fopen(in_filename, "rb");
    if (!blk_file) {
        cout << "failed to open blk" << endl;
        return 1;
    }

    {
        uint32_t magic = 0;
        fread(&magic, 4, 1, blk_file);
        if (magic != 0x6B6C62) { // blk\x00
            cout << "bad file magic" << endl;
            return 1;
        }
    }

    {
        uint32_t unk1 = 0;
        fread(&unk1, 4, 1, blk_file);
        if (unk1 != 0x10) {
            cout << "unk1 is not 0x10" << endl;
            return 1;
        }
    }

    uint8_t key[16] = {};
    fread(key, sizeof(key), 1, blk_file);
    fseek(blk_file, 16, SEEK_CUR); // skip the useless half of the key
    //hexdump("encrypted blk key:", key, sizeof(key));
    key_scramble1(key);
    key_scramble2(key);
    // this should also go into magic_constants.h, but it's small
    // this value goes through a lot of computation to get generated, but is always the same
    uint8_t hard_key[] = { 0xE3, 0xFC, 0x2D, 0x26, 0x9C, 0xC5, 0xA2, 0xEC, 0xD3, 0xF8, 0xC6, 0xD3, 0x77, 0xC2, 0x49, 0xB9 };
    for (int i = 0; i < 16; i++)
        key[i] ^= hard_key[i];
    //hexdump("decrypted blk key:", key, sizeof(key));

    uint16_t block_size = 0;
    fread(&block_size, sizeof(block_size), 1, blk_file);
    //cout << "0x" << hex << block_size << endl;

    fseek(blk_file, 0, SEEK_END);
    size_t size = ftell(blk_file);
    fseek(blk_file, 0x2A, SEEK_SET); // skip xorpad size

    auto* data = new uint8_t[size];
    fread(data, size, 1, blk_file);
    fclose(blk_file);

    /*
    uint8_t xorpad[4096] = {};
    create_decrypt_vector(key, data, size, xorpad, sizeof(xorpad));

    auto len = std::min((uint64_t)size, sizeof(xorpad));
    for (int i = 0; i < len; i++)
        data[i] ^= xorpad[i];
    */

    uint8_t xorpad[4096] = {};
    create_decrypt_vector(key, data, std::min((uint64_t)block_size, sizeof(xorpad)), xorpad, sizeof(xorpad));
    for (int i = 0; i < size; i++)
        data[i] ^= xorpad[i & 0xFFF];
    //dump_to_file("decrypted.bin", data, size);
    //dump_to_file("xorpad.bin", xorpad, sizeof(xorpad));

    //fwrite(data, size, 1, output);

    std::vector<size_t> mhy0_locs;
    size_t last_loc = 0;
    for (int i = 0; ; i++) {
        auto res = memmem(data + last_loc, size - last_loc, (void*)"mhy0", 4);
        if (res) {
            auto loc = (uint8_t*)res - data;
            mhy0_locs.push_back(loc);
            //cout << "found mhy0 at 0x" << hex << loc << endl;
            mhy0_extract(out_format, i, data + loc, size);
            last_loc = loc + 4;
        } else {
            break;
        }
    }

    //mhy0_extract(data, size);

    delete[] data;

    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        cout << "you need an input file" << endl;
        return 1;
    }
    if (!strcmp(argv[1], "batch")) {
        if (argc < 4) {
            cout << "you need input and output folders for batch mode" << endl;
            return 1;
        }

        auto base_path = std::filesystem::path(argv[2]);
        std::vector<std::filesystem::path> blk_paths;
        cout << "scanning for blks" << endl;
        try {
            for (auto& p : std::filesystem::recursive_directory_iterator(base_path)) {
                if (p.path().extension() == ".blk")
                    //cout << p.path().lexically_relative(base_path) << endl;
                    blk_paths.push_back(p.path().lexically_relative(base_path));
            }
        } catch (const std::exception& e) {
            cout << "failed to search for blk files with error: " << e.what() << endl;
            return 1;
        }
        cout << "found " << blk_paths.size() << " blks to extract" << endl;

        auto output_base = std::filesystem::path(argv[3]);
        //for (auto& p : blk_paths) {
        #pragma omp parallel for
        for (int i = 0; i < blk_paths.size(); i++) {
            auto p = blk_paths[i];
            cout << "processing " << p << "... ";

            auto input_path = base_path / p;
            auto output_path = (output_base / p).replace_extension(".%d.bin");
            auto output_dir = std::filesystem::path(output_path).remove_filename();
            //cout << output_path << endl;
            std::filesystem::create_directories(output_dir);
            int ret = extract_blk((char*)input_path.generic_string().c_str(), output_path.generic_string().c_str());

            if (!ret)
              cout << "ok" << endl;
        }
    } else {
        extract_blk(argv[1], "output%d.bin");
    }
}
