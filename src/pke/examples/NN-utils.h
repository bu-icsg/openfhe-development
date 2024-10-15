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

    /*
     * Context generating/loading stuff
     */
    Ctxt relu(Ctxt ct, int degree);
    Ctxt initialLayer(Ctxt ct);
    vector<Ctxt> conv1(Ctxt ct, int channels);
    Ctxt conv3x3(Ctxt ct, Ctxt weights, Ctxt bias, int size) ;
    Ctxt finalLayer(Ctxt ct);
    vector<double> read_values_from_file(string filename);
    vector<double> read_image(const char *filename, int width, int height, int channels);
};

#endif  //OPENFHE_NN_UTILS_H
