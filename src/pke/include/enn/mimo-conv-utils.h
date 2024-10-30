//
// Created by Şeyda Nur Güzelhan on 9/6/24.
//
#ifndef OPENFHE_MIMO_CONV_UTILS_H
#define OPENFHE_MIMO_CONV_UTILS_H

#include <iostream>
#include <vector>
#include <cmath>
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;
using namespace bigintdyn;

using Ptxt = Plaintext;
using Ctxt = Ciphertext<DCRTPoly>;

class ENN {
    CryptoContext<DCRTPoly> context;

public:
    ENN() {}

    vector<vector<vector<Ctxt>>> pack_images_mimo(CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keys, vector<vector<double>> x_s, int cn, int f, int iw, int ih, int padding);
    vector<vector<vector<double>>> pack_weights_mimo(vector<vector<double>> weights, int cn, int f, int img_size);
    vector<Ctxt> conv2d_mimo(vector<vector<vector<double>>> weight_list, vector<vector<vector<Ctxt>>> c_rotations, KeyPair<DCRTPoly> keys, int f);

    vector<vector<vector<Ctxt>>> pack_images_mimo_pt(CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keys, vector<vector<double>> x_s, int cn, int f, int iw, int ih, int padding);
    vector<Ctxt> conv2d_mimo_pt(vector<vector<vector<double>>> weight_list, vector<vector<vector<Ctxt>>> c_rotations, int f);

    Ctxt Automorph(Ctxt ct1, int i);
    PrivateKey<DCRTPoly> Automorph_poly(Ctxt ct1, PrivateKey<DCRTPoly> sk, int i);
    Ctxt relu(Ctxt ct, int degree);
};

#endif  //OPENFHE_MIMO_CONV_UTILS_H
