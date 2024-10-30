//
// Created by Şeyda Nur Güzelhan on 10/15/24.
//
#include <iostream>
#include <vector>
#include <cmath>
#include "openfhe.h"
#include "NN-utils.h"
#include "utils.h"
#include <iomanip>

using namespace std;
using namespace lbcrypto;

ENN ENN;

int main() {
    cout << fixed;
    cout << setprecision(0);
    int numSlots = 64;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim((1 << 16));
    parameters.SetMultiplicativeDepth(2);
    parameters.SetFirstModSize(60);
    parameters.SetScalingModSize(55);
    parameters.SetBatchSize(numSlots);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);

    //    vector<double> x1 = {0,2,3,0,2,3,4,5,3,0,0,2,6,1,0,1};
    int iw = 4;
    int ih = 4;
    int cn = numSlots / (iw*ih);

    vector<vector<double>> x_inputs;
    vector<double> x1 = {0,2,3,0,2,3,4,5,3,0,0,2,6,1,0,1};
    vector<double> x2 = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
    x_inputs.push_back(x1);
    x_inputs.push_back(x2);

    vector<double> x_input;

//    int fh = 3;
//    int fw = 3;

    for (int i=0; i<cn/x_inputs.size(); i++){
        for (int j=0; j<x_inputs.size(); j++){
            x_input.insert(x_input.end(), x_inputs[j].begin(), x_inputs[j].end());
        }
    }

    vector<vector<double>> weights;
    weights.push_back({1,2,1,0,1,1,2,1,1});
    weights.push_back({-1,-2,-1,0,-1,-1,-2,-1,-1});
    weights.push_back({1,2,1,0,1,1,2,1,1});
    weights.push_back({-1,-2,-1,0,-1,-1,-2,-1,-1});
    vector<double> weights_input;
    for (int i=0; i<cn/weights.size(); i++){
        for (int j=0; j<weights.size(); j++){
            weights_input.insert(weights_input.end(), weights[j].begin(), weights[j].end());
        }
    }

    int ci_t = x_inputs.size();
    int co_t = weights.size();
    int ci = ceil((double)ci_t / cn);
    int co = ceil((double)co_t / cn);

//    weights.push_back({1,2,1,0,1,1,2,1,1});
//    weights.push_back({-1,-2,-1,0,-1,-1,-2,-1,-1});

    Ptxt pt1 = cc->MakeCKKSPackedPlaintext(x_input);
    pt1->SetLength(numSlots);

    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    Ctxt ct1 = cc->Encrypt(keys.publicKey, pt1);

    vector<vector<double>> weight_list{9};
    for (int j=0; j<ci; j++){
        for(int i=0; i < weights.size(); i++){
            weight_list[0].insert(weight_list[0].end(), {0, 0, 0, 0, 0, weights[i][0], weights[i][0], weights[i][0], 0, weights[i][0], weights[i][0], weights[i][0], 0, weights[i][0], weights[i][0], weights[i][0]});
            weight_list[1].insert(weight_list[1].end(), {0, 0, 0, 0, weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1]});
            weight_list[2].insert(weight_list[2].end(), {0, 0, 0, 0, weights[i][2], weights[i][2], weights[i][2], 0, weights[i][2], weights[i][2], weights[i][2], 0, weights[i][2], weights[i][2], weights[i][2], 0});
            weight_list[3].insert(weight_list[3].end(), {0, weights[i][3], weights[i][3], weights[i][3], 0, weights[i][3], weights[i][3], weights[i][3], 0, weights[i][3], weights[i][3], weights[i][3], 0, weights[i][3], weights[i][3], weights[i][3]});
            weight_list[4].insert(weight_list[4].end(), {weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4]});
            weight_list[5].insert(weight_list[5].end(), {weights[i][5], weights[i][5], weights[i][5], 0, weights[i][5], weights[i][5], weights[i][5], 0, weights[i][5], weights[i][5], weights[i][5], 0, weights[i][5], weights[i][5], weights[i][5], 0});
            weight_list[6].insert(weight_list[6].end(), {0, weights[i][6], weights[i][6], weights[i][6], 0, weights[i][6], weights[i][6], weights[i][6], 0, weights[i][6], weights[i][6], weights[i][6], 0, 0, 0, 0});
            weight_list[7].insert(weight_list[7].end(), {weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], 0, 0, 0, 0});
            weight_list[8].insert(weight_list[8].end(), {weights[i][8], weights[i][8], weights[i][8], 0, weights[i][8], weights[i][8], weights[i][8], 0, weights[i][8], weights[i][8], weights[i][8], 0, 0, 0, 0, 0});
        }
    }


    cc->EvalRotateKeyGen(keys.secretKey, {-5,-4,-3,-1,1,3,4,5,ih*iw});

    vector<vector<Ctxt>> c_rotations{9};
    for (int i=0; i<ci_t; i++){
        c_rotations[i].push_back(cc->EvalRotate(ct1, -5));
        c_rotations[i].push_back(cc->EvalRotate(ct1, -4));
        c_rotations[i].push_back(cc->EvalRotate(ct1, -3));
        c_rotations[i].push_back(cc->EvalRotate(ct1, -1));
        c_rotations[i].push_back(ct1);
        c_rotations[i].push_back(cc->EvalRotate(ct1, 1));
        c_rotations[i].push_back(cc->EvalRotate(ct1, 3));
        c_rotations[i].push_back(cc->EvalRotate(ct1, 4));
        c_rotations[i].push_back(cc->EvalRotate(ct1, 5));
        ct1 = cc->EvalRotate(ct1, ih*iw);
    }

    vector<Ctxt> inter_out_ct;
    for (int j = 0; j < co; j++) {
        vector<Ctxt> inter_in_ct;
        for(int l=0; l < ci_t; l++){
            vector<Ctxt> conv_ct;
            for (int k = 0; k < 9; k++) {
                Ptxt weight_pt = cc->MakeCKKSPackedPlaintext(weight_list[k]);
                Ctxt cMult     = cc->EvalMult(weight_pt, c_rotations[l][k]);
                conv_ct.push_back(cMult);
            }
            Ctxt inter_conv_sum = cc->EvalAddMany(conv_ct);
            inter_in_ct.push_back(inter_conv_sum);

            Ptxt res;
            cc->Decrypt(keys.secretKey, inter_in_ct[l], &res);
            res->SetLength(numSlots);
            cout << "out: " << l << endl;
            cout << res << endl;

        }
        Ctxt inter_out_sum = cc->EvalAddMany(inter_in_ct);
        inter_out_ct.push_back(inter_out_sum);
    }

    for (int i=0; i<co; i++){
        Ptxt res;
        cc->Decrypt(keys.secretKey, inter_out_ct[i], &res);
        res->SetLength(numSlots);
        cout << "out: " << i << endl;
        cout << res << endl;
    }

    return 0;
}
