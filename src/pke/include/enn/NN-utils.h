//
// Created by Şeyda Nur Güzelhan on 9/6/24.
//
#ifndef OPENFHE_NN_UTILS_H
#define OPENFHE_NN_UTILS_H

#include <iostream>
#include <vector>
#include <cmath>
#include "openfhe.h"
#define STB_IMAGE_IMPLEMENTATION
#include "stb-image.h"

using namespace std;
using namespace lbcrypto;
using Ptxt = Plaintext;
using Ctxt = Ciphertext<DCRTPoly>;

class ENN {
    CryptoContext<DCRTPoly> context;

public:
    ENN() {}

    Ctxt relu(Ctxt ct, int degree);
    vector<vector<vector<double>>> pack_weights_mimo(vector<vector<double>> weights, int cn, int f, int img_size);
    vector<vector<vector<Ctxt>>> pack_images_mimo(CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keys, vector<vector<double>> x_s, int cn, int f, int iw, int ih, int padding);
    vector<Ctxt> conv2d_mimo(vector<vector<vector<double>>> weight_list, vector<vector<vector<Ctxt>>> c_rotations, int f);
    vector<double> read_values_from_file(string filename);
    vector<double> read_image(const char *filename, int width, int height, int channels);

};

#endif  //OPENFHE_NN_UTILS_H
