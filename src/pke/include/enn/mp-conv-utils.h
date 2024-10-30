//
// Created by Şeyda Nur Güzelhan on 10/30/24.
//

#ifndef OPENFHE_MP_CONV_UTILS_H
#define OPENFHE_MP_CONV_UTILS_H

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

    vector<vector<vector<double>>> pack_weights_mp(vector<vector<double>> weights, int cn, int f, int iw, int ih, int mp_factor);
    vector<vector<vector<Ctxt>>> pack_images_mp(CryptoContext<DCRTPoly> cc, KeyPair<DCRTPoly> keys, vector<vector<double>> x_s, int cn, int f, int iw, int ih, int padding, int mp_factor);
    vector<Ctxt> conv2d_mp(vector<vector<vector<double>>> weight_list, vector<vector<vector<Ctxt>>> c_rotations, int f, int iw, int padding, KeyPair<DCRTPoly> keys, int mp_factor, int cn, int ci, int co);
};

#endif  //OPENFHE_MP_CONV_UTILS_H
