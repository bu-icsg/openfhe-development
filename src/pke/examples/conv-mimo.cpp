//
// Created by Şeyda Nur Güzelhan on 10/16/24.
//
#include <iostream>
#include <vector>
#include "openfhe.h"
#include "enn/mimo-conv-utils.h"
#include "enn/utils.h"

using namespace std;
using namespace lbcrypto;

ENN ENN;

int main() {
    cout << fixed << setprecision(0);
    int numSlots = 32;

    vector<vector<double>> x_s;
    x_s.push_back({0,2,3,0,2,3,4,5,3,0,0,2,6,1,0,1});
    x_s.push_back({1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1});

    vector<vector<double>> weights;
    weights.push_back({1,2,1,0,1,1,2,1,1});
    weights.push_back({-1,-2,-1,0,-1,-1,-2,-1,-1});

    int iw = sqrt(x_s[0].size());
    int ih = iw;
    int cn = numSlots / (iw*ih);
    int ci = x_s.size();
    int padding = 1;
    int f = sqrt(weights[0].size());

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim((1 << 16));
    parameters.SetMultiplicativeDepth(2);
    parameters.SetFirstModSize(59);
    parameters.SetScalingModSize(59);
    parameters.SetBatchSize(min(cn, ci)*ih*iw);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    vector<vector<double>> conv_result_plain = conv2d(x_s, weights, padding, 1);

    vector<vector<vector<Ctxt>>> c_rotations;
    vector<vector<vector<double>>> weight_list;
    vector<Ctxt> conv_result_cipher;

    int flag_encrypted_model = 1;
    if (flag_encrypted_model){
        c_rotations = ENN.pack_images_mimo(cc, keys, x_s, cn, f, iw, ih, padding);
        weight_list = ENN.pack_weights_mimo(weights, cn, f, iw*ih);
        conv_result_cipher = ENN.conv2d_mimo(weight_list, c_rotations, keys, f);
    }
    else {
        c_rotations = ENN.pack_images_mimo(cc, keys, x_s, cn, f, iw, ih, padding);
        weight_list = ENN.pack_weights_mimo(weights, cn, f, iw*ih);
        conv_result_cipher = ENN.conv2d_mimo_pt(weight_list, c_rotations, f);
    }

    cout << endl;
    for (int i=0; i< conv_result_cipher.size(); i++){
        Ptxt res;
        cc->Decrypt(keys.secretKey, conv_result_cipher[i], &res);
        res->SetLength(numSlots);
        cout << "ENN output " << i << ": " << res;
    }
    cout << endl;

    compare_conv_results(conv_result_plain, conv_result_cipher, 0.000001, keys);

    return 0;
}

