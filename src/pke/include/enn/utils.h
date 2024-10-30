//
// Created by Şeyda Nur Güzelhan on 9/6/24.
//

#ifndef OPENFHE_UTILS_H

#include <iostream>
#include <vector>
#include <cmath>
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;
using namespace bigintdyn;

using Ptxt = Plaintext;
using Ctxt = Ciphertext<DCRTPoly>;

void compare_vectors(vector<double> v1, vector<double> v2, double precision) {
    int flag = 1;
    for (int i = 0; i < v1.size(); i++) {
        if ((v1[i] - v2[i]) > precision) {
//            cout << "v1[i] - v2[i]: " << v1[i] - v2[i] << endl;
            flag = 0;
        };
    };
    if (flag) {
        cout << "Results are the same!" << endl;
    }
    else {
        cout << "Results are different!" << endl;
//        cout << v1 << endl << endl;
//        cout << v2 << endl << endl;
    };
}

void compare_conv_results(vector<vector<double>> v1, vector<Ctxt> ct, double precision, KeyPair<DCRTPoly> keys) {

    auto cc = ct[0]->GetCryptoContext();
    auto numSlots = ct[0]->GetSlots();

    vector<double> conv_result_decrypted;
    for (int i=0; i<ct.size(); i++){
        Ptxt res;
        cc->Decrypt(keys.secretKey, ct[i], &res);
        res->SetLength(numSlots);
        vector<double> vals = res->GetRealPackedValue();
        conv_result_decrypted.insert(conv_result_decrypted.end(), vals.begin(), vals.end());
    }

    vector<double> v1_flattened;
    for (int i = 0; i < v1.size(); ++i) {
        v1_flattened.insert(v1_flattened.end(), v1[i].begin(), v1[i].end());
    }
    compare_vectors(v1_flattened, conv_result_decrypted, precision);
}

vector<vector<vector<double>>> ctxt_to_vector(Ctxt ct){
    int no_limbs = ct->GetElements()[0].GetNumOfElements();
    int N = ct->GetCryptoContext()->GetRingDimension();
    vector<vector<vector<double>>> elems(2, vector<vector<double>>(no_limbs, vector<double>(N)));
    for(int i=0; i<2; i++){
        for(int j=0; j<no_limbs; j++){
            for(int k=0; k<N; k++) {
                elems[i][j][k] = ct->GetElements()[i].GetAllElements()[j][k].ConvertToInt<uint64_t>();
            }
        }
    }
    return elems;
}

// Function to convert a flat vector (1D) into a 2D matrix (rows x cols)
vector<vector<double>> flatten_to_matrix(const vector<double>& flat_vector, int rows, int cols) {
    vector<vector<double>> matrix(rows, vector<double>(cols));
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            matrix[i][j] = flat_vector[i * cols + j];
        }
    }
    return matrix;
}

// Function to apply 2D convolution to multiple input channels and filters
vector<vector<double>> convolve2d(const vector<vector<double>>& input, const vector<vector<double>>& filter, int padding = 1, int stride = 1) {
    int input_size = input.size();
    int filter_size = filter.size();
    int output_size = (input_size + 2 * padding - filter_size) / stride + 1;

    // Initialize the output matrix
    vector<vector<double>> output(output_size, vector<double>(output_size, 0.0));

    // Apply padding to input
    vector<vector<double>> padded_input(input_size + 2 * padding, vector<double>(input_size + 2 * padding, 0.0));
    for (int i = 0; i < input_size; ++i) {
        for (int j = 0; j < input_size; ++j) {
            padded_input[i + padding][j + padding] = input[i][j];
        }
    }

    // Perform convolution
    for (int i = 0; i < output_size; ++i) {
        for (int j = 0; j < output_size; ++j) {
            double sum = 0.0;
            for (int fi = 0; fi < filter_size; ++fi) {
                for (int fj = 0; fj < filter_size; ++fj) {
                    sum += padded_input[i + fi][j + fj] * filter[fi][fj];
                }
            }
            output[i][j] = sum;
        }
    }

    return output;
}

// Main convolution function that handles multiple input channels and filters
vector<vector<double>> conv2d(const vector<vector<double>>& inputs, const vector<vector<double>>& filters, int padding, int verbose) {
    // Convert each flattened input into a 4x4 matrix
    int img_width = sqrt(inputs[0].size());
    int img_height = img_width;
    int f = sqrt(filters[0].size());

    vector<vector<vector<double>>> input_channels;
    for (const auto& input : inputs) {
        input_channels.push_back(flatten_to_matrix(input, img_width, img_height)); // Assuming 4x4 images
    }

    // Convert each flattened filter into a 3x3 matrix
    vector<vector<vector<double>>> filter_matrices;
    for (const auto& filter : filters) {
        filter_matrices.push_back(flatten_to_matrix(filter, f, f)); // Assuming 3x3 filters
    }

    // Vector to store the output for each filter (4x4 for each filter)
    vector<vector<vector<double>>> output_per_filter;

    // Perform convolution for each filter
    for (const auto& filter : filter_matrices) {
        // Initialize the result matrix for this filter
        vector<vector<double>> filter_output(img_width, vector<double>(img_height, 0.0));

        // Perform convolution over all input channels and sum them
        for (const auto& input_channel : input_channels) {
            vector<vector<double>> convolved = convolve2d(input_channel, filter, padding);
            for (int i = 0; i < img_width; ++i) {
                for (int j = 0; j < img_height; ++j) {
                    filter_output[i][j] += convolved[i][j]; // Sum across input channels
                }
            }
        }

        // Store this filter's output
        output_per_filter.push_back(filter_output);
    }

    // Print the output for each filter in flattened form
    if (verbose) {
        for (int j = 0; j < output_per_filter.size(); ++j) {
            cout << "Output " << j << ": ";
            for (const auto& row : output_per_filter[j]) {
                for (double val : row) {
                    cout << val << ", ";
                }
            }
            cout << endl;
        }
    }
    // Flatten the 2D array into 1D
    vector<vector<double>> output_2D(filters.size());
    for (int j = 0; j < output_per_filter.size(); ++j) {
        for (int i = 0; i < img_width; ++i) {
            output_2D[j].insert(output_2D[j].end(), output_per_filter[j][i].begin(), output_per_filter[j][i].end());
        }
    }
    return output_2D;
}

// type_check:
//int status;
//const char* mangled_name = typeid(element).name();
//char* demangled_name     = abi::__cxa_demangle(mangled_name, nullptr, nullptr, &status);
//std::cout << "Type: " << (status == 0 ? demangled_name : mangled_name) << std::endl;
//free(demangled_name);

#define OPENFHE_UTILS_H

#endif  //OPENFHE_UTILS_H
