// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include <iostream>
#include <time.h>

using namespace std;
using namespace seal;

void example_substringmatch_test()
{
    /************ Set up encryption parameters ************/
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 4096;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    SEALContext context(parms);
    auto qualifiers = context.first_context_data()->qualifiers();
    cout << "Batching enabled: " << boolalpha << qualifiers.using_batching << endl;

    /************ Generate encryption context ************/
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;

    /******** Encode input IMSI for substring match *********/
    clock_t begin_time = clock();
    vector<uint64_t> input_imsi_matrix(slot_count, 0ULL);
    std::string input_imsi = "imsi-2089300000003";

    for (long i = 0; i < input_imsi.size(); ++i) {
        input_imsi_matrix[i] = (uint64_t) input_imsi[i];
    }

    Plaintext plain_input_imsi_matrix;
    batch_encoder.encode(input_imsi_matrix, plain_input_imsi_matrix);
    cout << endl;
    // cout << "Input plaintext IMSI matrix:" << endl;
    // print_matrix(input_imsi_matrix, row_size);

    /******** Encode mask for substring match *********/
    vector<uint64_t> mask_matrix(slot_count, 0ULL);
    std::string mask = "imsi-";

    for (long i = 0; i < mask.size(); ++i) {
        mask_matrix[i] = (uint64_t) mask[i];
    }

    Plaintext plain_mask_matrix;
    batch_encoder.encode(mask_matrix, plain_mask_matrix);
    cout << endl;
    // cout << "Input plaintext IMSI matrix:" << endl;
    // print_matrix(input_imsi_matrix, row_size);

    /********* encrypt the encoded plaintext INPUT IMSI *********/
    Ciphertext encrypted_input_imsi_matrix;
    Ciphertext encrypted_mask_matrix;
    // cout << "Encrypt plain_input_imsi_matrix to encrypted_matrix." << endl;
    encryptor.encrypt(plain_input_imsi_matrix, encrypted_input_imsi_matrix);
    encryptor.encrypt(plain_mask_matrix, encrypted_mask_matrix);
    // cout << "    + Noise budget in encrypted_input_imsi_matrix: " << decryptor.invariant_noise_budget(encrypted_input_imsi_matrix) << " bits" << endl;
    cout << "++++++++++ Encryption Latency: ";
    std::cout << float( clock () - begin_time ) /  CLOCKS_PER_SEC << endl;

    /********* Calculate the difference *********/
    begin_time = clock();
    Ciphertext encrypted_delta_matrix;
    evaluator.sub(encrypted_input_imsi_matrix, encrypted_mask_matrix, encrypted_delta_matrix);
    // cout << "    + Noise budget in encrypted_delta_matrix: " << decryptor.invariant_noise_budget(encrypted_delta_matrix) << " bits" << endl;
    Plaintext plain_delta_result;
    vector<uint64_t> pod_result(slot_count, 0ULL);
    decryptor.decrypt(encrypted_delta_matrix, plain_delta_result);
    batch_encoder.decode(plain_delta_result, pod_result);


    /********* Recover mask with values *********/
    // vector<uint64_t> sub_matrix(counter, 0ULL);
    string target_idx;
    std::string substring;
    for (long i = 0; i < pod_result.size(); ++i) {
        // printf("val[%lu] = %llx\n", i, pod_result[i]);
        // std::cout << std::setw(16) << std::setfill('0') << std::hex << pod_result[i] << endl;
        substring += (char) pod_result[i];
    }


    cout << "++++++++++ Match Latency: ";
    std::cout << float( clock () - begin_time ) /  CLOCKS_PER_SEC << endl;
    cout << "++++++++++ Match Results: " << substring << endl;
    cout << "\n" << endl;

    return;
}