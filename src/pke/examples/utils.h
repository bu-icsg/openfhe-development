//
// Created by Şeyda Nur Güzelhan on 9/6/24.
//

#ifndef OPENFHE_UTILS_H

#include <iostream>
#include <vector>
#include <cmath>

using namespace std;

void compare_vectors(vector<double> v1, vector<double> v2, int size, double precision){

    int flag = 1;
    for(int i=0; i<size; i++){
        if ((v1[i] - v2[i]) > precision) {
            flag = 0;
        };
    };
    if (flag){
        cout << "Vectors are the same!" << endl;
    }
    else {
        cout << "Vectors are different!" << endl;

    };
};
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
void conv2d(const vector<vector<double>>& inputs, const vector<vector<double>>& filters, int padding) {
    // Convert each flattened input into a 4x4 matrix
    vector<vector<vector<double>>> input_channels;
    for (const auto& input : inputs) {
        input_channels.push_back(flatten_to_matrix(input, 4, 4)); // Assuming 4x4 images
    }

    // Convert each flattened filter into a 3x3 matrix
    vector<vector<vector<double>>> filter_matrices;
    for (const auto& filter : filters) {
        filter_matrices.push_back(flatten_to_matrix(filter, 3, 3)); // Assuming 3x3 filters
    }

    // Vector to store the output for each filter (4x4 for each filter)
    vector<vector<vector<double>>> output_per_filter;

    // Perform convolution for each filter
    for (const auto& filter : filter_matrices) {
        // Initialize the result matrix for this filter
        vector<vector<double>> filter_output(4, vector<double>(4, 0.0));

        // Perform convolution over all input channels and sum them
        for (const auto& input_channel : input_channels) {
            vector<vector<double>> convolved = convolve2d(input_channel, filter, padding);
            for (int i = 0; i < 4; ++i) {
                for (int j = 0; j < 4; ++j) {
                    filter_output[i][j] += convolved[i][j]; // Sum across input channels
                }
            }
        }

        // Store this filter's output
        output_per_filter.push_back(filter_output);
    }

    // Print the output for each filter in flattened form
    for (int f = 0; f < output_per_filter.size(); ++f) {
        cout << "Channel " << f << ": ";
        for (const auto& row : output_per_filter[f]) {
            for (double val : row) {
                cout << val << ", ";
            }
        }
        cout << endl;
    }
}


#define OPENFHE_UTILS_H

#endif  //OPENFHE_UTILS_H
