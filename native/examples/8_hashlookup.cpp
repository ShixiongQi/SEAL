// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include <iostream>
#include <time.h>

using namespace std;
using namespace seal;

void print_vec(std::vector <uint64_t> const &a) {
   std::cout << "The vector elements are : ";

   for(int i=0; i < a.size(); i++)
   std::cout << a.at(i) << ' ';
}

// Utility function to read <K,V> CSV data from file
std::vector<std::pair<std::string, std::string>> read_csv(std::string filename)
{
    std::vector<std::pair<std::string, std::string>> dataset;
    std::ifstream data_file(filename);

    if (!data_file.is_open())
        throw std::runtime_error(
            "Error: This example failed trying to open the data file: " + filename +
            "\n           Please check this file exists and try again.");

    std::vector<std::string> row;
    std::string line, entry, temp;

    if (data_file.good()) {
        // Read each line of file
        while (std::getline(data_file, line)) {
        row.clear();
        std::stringstream ss(line);
        while (getline(ss, entry, ',')) {
            row.push_back(entry);
        }
        // Add key value pairs to dataset
        dataset.push_back(std::make_pair(row[0], row[1]));
        }
  }

  data_file.close();
  return dataset;
}

void example_hashlookup_test()
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

    /************ Read in the UE database ************/
    std::string db_filename = "/users/sqi009/SEAL/native/examples/ue_dataset.csv";
    std::vector<std::pair<std::string, std::string>> ue_db;
    try {
        ue_db = read_csv(db_filename);
    } catch (std::runtime_error& e) {
        std::cerr << "\n" << e.what() << std::endl;
        exit(1);
    }
    std::cout << "ue_db size: " << ue_db.size() << '\n';

    /** Generating the Plain text representation of UE DB **/
    size_t slot_count = batch_encoder.slot_count();
    size_t row_size = slot_count / 2;
    cout << "Plaintext matrix row size: " << row_size << endl;
    vector<uint64_t> imsi_matrix(slot_count, 0ULL);
    // vector<uint64_t> index_matrix(slot_count, 0ULL);

    int counter = 0;
    for (const auto& imsi_index_pair : ue_db) {
        if (0) {
        std::cout << "\t\timsi_index_pair.first size = "
                    << imsi_index_pair.first.size() << " ("
                    << imsi_index_pair.first << ")"
                    << "\timsi_index_pair.second size = "
                    << imsi_index_pair.second.size() << " ("
                    << imsi_index_pair.second << ")" << std::endl;
        }
        // all_imsi += imsi_index_pair.first;
        for (long i = 0; i < imsi_index_pair.first.size(); ++i) {
            imsi_matrix[counter * imsi_index_pair.first.size() + i] = (uint64_t) imsi_index_pair.first[i];
            // if (counter * imsi_index_pair.first.size() <= i < counter * imsi_index_pair.first.size() + imsi_index_pair.second.size()) {
            //     index_matrix[counter * imsi_index_pair.first.size() + i] = (uint64_t) imsi_index_pair.second[i];
            // } else {
            //     index_matrix[counter * imsi_index_pair.first.size() + i] = (uint64_t) 0;
            // }
        }
        counter++;
    }
    // std::cout << "all_imsi: " << all_imsi << '\n';
    // print_matrix(imsi_matrix, row_size);
    Plaintext plain_imsi_matrix;
    batch_encoder.encode(imsi_matrix, plain_imsi_matrix);

    /******** Test encoder ********/
    vector<uint64_t> pod_result;
    // cout << "    + Decode plaintext matrix ...... Correct." << endl;
    batch_encoder.decode(plain_imsi_matrix, pod_result);
    // print_matrix(pod_result, row_size);
    // print_vec(pod_result);

    /********* encrypt the encoded plaintext IMSI DB *********/
    Ciphertext encrypted_imsi_matrix;
    // cout << "Encrypt plain_imsi_matrix to encrypted_matrix." << endl;
    encryptor.encrypt(plain_imsi_matrix, encrypted_imsi_matrix);
    // cout << "    + Noise budget in encrypted_imsi_matrix: " << decryptor.invariant_noise_budget(encrypted_imsi_matrix) << " bits" << endl;

    /******** Encode input IMSI for lookup *********/
    clock_t begin_time = clock();
    vector<uint64_t> input_imsi_matrix(slot_count, 0ULL);
    // std::string input_imsi = "imsi-2089300000003";
    std::string input_imsi;
    cout<<"Enter IMSI: ";
    cin>>input_imsi;
    int counter2 = 0;
    for (const auto& imsi_index_pair : ue_db) {
        for (long i = 0; i < imsi_index_pair.first.size(); ++i) {
            input_imsi_matrix[counter2 * imsi_index_pair.first.size() + i] = (uint64_t) input_imsi[i];
        }
        counter2++;
    }
    Plaintext plain_input_imsi_matrix;
    batch_encoder.encode(input_imsi_matrix, plain_input_imsi_matrix);
    cout << endl;
    // cout << "Input plaintext IMSI matrix:" << endl;
    // print_matrix(input_imsi_matrix, row_size);

    /********* encrypt the encoded plaintext INPUT IMSI *********/
    Ciphertext encrypted_input_imsi_matrix;
    // cout << "Encrypt plain_input_imsi_matrix to encrypted_matrix." << endl;
    encryptor.encrypt(plain_input_imsi_matrix, encrypted_input_imsi_matrix);
    // cout << "    + Noise budget in encrypted_input_imsi_matrix: " << decryptor.invariant_noise_budget(encrypted_input_imsi_matrix) << " bits" << endl;
    cout << "++++++++++ Encryption Latency: ";
    std::cout << float( clock () - begin_time ) /  CLOCKS_PER_SEC << endl;


    
    /********* Calculate the difference *********/
    begin_time = clock();
    // print_line(__LINE__);
    // cout << "Compute kq - k" << endl;
    Ciphertext encrypted_delta_matrix;
    evaluator.sub(encrypted_imsi_matrix, encrypted_input_imsi_matrix, encrypted_delta_matrix);
    // cout << "    + size of encrypted_delta_matrix: " << encrypted_delta_matrix.size() << endl;
    // cout << "    + noise budget in encrypted_delta_matrix: " << decryptor.invariant_noise_budget(encrypted_delta_matrix) << " bits"
    //      << endl;
    // cout << "    + decryption of encrypted_delta_matrix: ";
    // Plaintext decrypted_result;
    // vector<uint64_t> delta_result;
    // decryptor.decrypt(encrypted_delta_matrix, decrypted_result);
    // batch_encoder.decode(decrypted_result, delta_result);
    // print_matrix(delta_result, row_size);
    // cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(encrypted_delta_matrix) << " bits" << endl;

    /********* Fermat's little theorem *********/
    // Plaintext prime modulus
    // uint64_t p = 131;
    // evaluator.exponentiate_inplace(encrypted_delta_matrix, p-1, relin_keys);
    // cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(encrypted_delta_matrix) << " bits" << endl;

    /********* Negate the ciphertext *********/
    // evaluator.negate_inplace(encrypted_delta_matrix);
    // Plaintext plain_one("1");
    // evaluator.add_plain_inplace(encrypted_delta_matrix, plain_one);

    // /********* multiply mask with values *********/
    // Ciphertext encrypted_results_matrix;
    // evaluator.multiply(encrypted_index_matrix, encrypted_delta_matrix, encrypted_results_matrix);

    // cout << "    + Noise budget in result: " << decryptor.invariant_noise_budget(encrypted_delta_matrix) << " bits" << endl;

    Plaintext plain_delta_result;
    // print_line(__LINE__);
    // cout << "Decrypt and decode result." << endl;
    decryptor.decrypt(encrypted_delta_matrix, plain_delta_result);
    batch_encoder.decode(plain_delta_result, pod_result);
    // cout << "    + Result plaintext matrix ...... Correct." << endl;
    // print_matrix(pod_result, row_size);
    // print_vec(pod_result);

    /********* Recover mask with values *********/
    int counter3 = 0;
    vector<uint64_t> mask_matrix(counter, 0ULL);
    string target_idx;
    for (const auto& imsi_index_pair : ue_db) {
        for (long i = 0; i < imsi_index_pair.first.size(); ++i) {
            mask_matrix[counter3] += pod_result[counter3 * imsi_index_pair.first.size() + i];
        }
        if (mask_matrix[counter3] == 0) {
            target_idx = imsi_index_pair.second;
            break;
        }
            
        counter3++;
    }
    // cout << "\n" << endl;
    // print_vec(mask_matrix);
    // cout << "\n" << endl;
    // cout << "Matched Index: " << counter3 << endl;
    cout << "++++++++++ Lookup Latency: ";
    std::cout << float( clock () - begin_time ) /  CLOCKS_PER_SEC << endl;
    cout << "++++++++++ Lookup Results: " << target_idx << endl;
    cout << "\n" << endl;

    return;
}