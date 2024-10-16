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
    int numSlots = 32;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim((1 << 16));
    parameters.SetMultiplicativeDepth(2);
    parameters.SetFirstModSize(60);
    parameters.SetScalingModSize(55);
    parameters.SetBatchSize(numSlots);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    //    vector<double> x1 = {0,2,3,0,2,3,4,5,3,0,0,2,6,1,0,1};
    int iw = 4;
    int ih = 4;
    int cn = numSlots / (iw*ih);

    vector<vector<double>> x_s;
    x_s.push_back({0,2,3,0,2,3,4,5,3,0,0,2,6,1,0,1});
    x_s.push_back({1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1});
    x_s.push_back({1,0,6,0,2,0,0,5,6,0,1,2,1,0,0,1});
    x_s.push_back({-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1});

    vector<vector<double>> weights;
    weights.push_back({1,2,1,0,1,1,2,1,1});
    weights.push_back({-1,-2,-1,0,-1,-1,-2,-1,-1});
    weights.push_back({0,0,1,0,1,0,1,0,0});
    weights.push_back({-1,-1,-1,-1,-1,-1,-1,-1,-1});
    weights.push_back({0,0,1,0,1,0,1,0,0});
    weights.push_back({-1,-1,-1,-1,-1,-1,-1,-1,-1});
    //    weights.push_back({-1,-1,-1,-1,-1,-1,-1,-1,-1});

    // Perform the convolution
    conv2d(x_s, weights, 1);

    int ci = x_s.size();
    int co = weights.size();
    int ci_cn = ceil((double)ci / cn);
    int co_cn = ceil((double)co / cn);

    vector<vector<double>> x_inputs(ci_cn);
    for (int i=0; i<ci_cn; i++){
        for (int j=0; j<cn; j++){
            x_inputs[i].insert(x_inputs[i].end(), x_s[i*cn+j].begin(), x_s[i*cn+j].end());
        }
    }

    //    for (int i=0; i<ci_cn; i++){
    //        cout << "pt: " << x_inputs[i] << endl;
    //    }

    vector<Ctxt> ct_inputs;
    for (int i=0; i<ci_cn; i++){
        Ptxt temp = cc->MakeCKKSPackedPlaintext(x_inputs[i]);
        ct_inputs.push_back(cc->Encrypt(keys.publicKey, temp));
    }


    vector<vector<vector<double>>> weight_list(co_cn, vector<vector<double>>(9));
    for (int j=0; j<co_cn; j++){
        for(int i=0; i < cn; i++){
            weight_list[j][0].insert(weight_list[j][0].end(), {0, 0, 0, 0, 0, weights[i+j*cn][0], weights[i+j*cn][0], weights[i+j*cn][0], 0, weights[i+j*cn][0], weights[i+j*cn][0], weights[i+j*cn][0], 0, weights[i+j*cn][0], weights[i+j*cn][0], weights[i+j*cn][0]});
            weight_list[j][1].insert(weight_list[j][1].end(), {0, 0, 0, 0, weights[i+j*cn][1], weights[i+j*cn][1], weights[i+j*cn][1], weights[i+j*cn][1], weights[i+j*cn][1], weights[i+j*cn][1], weights[i+j*cn][1], weights[i+j*cn][1], weights[i+j*cn][1], weights[i+j*cn][1], weights[i+j*cn][1], weights[i+j*cn][1]});
            weight_list[j][2].insert(weight_list[j][2].end(), {0, 0, 0, 0, weights[i+j*cn][2], weights[i+j*cn][2], weights[i+j*cn][2], 0, weights[i+j*cn][2], weights[i+j*cn][2], weights[i+j*cn][2], 0, weights[i+j*cn][2], weights[i+j*cn][2], weights[i+j*cn][2], 0});
            weight_list[j][3].insert(weight_list[j][3].end(), {0, weights[i+j*cn][3], weights[i+j*cn][3], weights[i+j*cn][3], 0, weights[i+j*cn][3], weights[i+j*cn][3], weights[i+j*cn][3], 0, weights[i+j*cn][3], weights[i+j*cn][3], weights[i+j*cn][3], 0, weights[i+j*cn][3], weights[i+j*cn][3], weights[i+j*cn][3]});
            weight_list[j][4].insert(weight_list[j][4].end(), {weights[i+j*cn][4], weights[i+j*cn][4], weights[i+j*cn][4], weights[i+j*cn][4], weights[i+j*cn][4], weights[i+j*cn][4], weights[i+j*cn][4], weights[i+j*cn][4], weights[i+j*cn][4], weights[i+j*cn][4], weights[i+j*cn][4], weights[i+j*cn][4], weights[i+j*cn][4], weights[i+j*cn][4], weights[i+j*cn][4], weights[i+j*cn][4]});
            weight_list[j][5].insert(weight_list[j][5].end(), {weights[i+j*cn][5], weights[i+j*cn][5], weights[i+j*cn][5], 0, weights[i+j*cn][5], weights[i+j*cn][5], weights[i+j*cn][5], 0, weights[i+j*cn][5], weights[i+j*cn][5], weights[i+j*cn][5], 0, weights[i+j*cn][5], weights[i+j*cn][5], weights[i+j*cn][5], 0});
            weight_list[j][6].insert(weight_list[j][6].end(), {0, weights[i+j*cn][6], weights[i+j*cn][6], weights[i+j*cn][6], 0, weights[i+j*cn][6], weights[i+j*cn][6], weights[i+j*cn][6], 0, weights[i+j*cn][6], weights[i+j*cn][6], weights[i+j*cn][6], 0, 0, 0, 0});
            weight_list[j][7].insert(weight_list[j][7].end(), {weights[i+j*cn][7], weights[i+j*cn][7], weights[i+j*cn][7], weights[i+j*cn][7], weights[i+j*cn][7], weights[i+j*cn][7], weights[i+j*cn][7], weights[i+j*cn][7], weights[i+j*cn][7], weights[i+j*cn][7], weights[i+j*cn][7], weights[i+j*cn][7], 0, 0, 0, 0});
            weight_list[j][8].insert(weight_list[j][8].end(), {weights[i+j*cn][8], weights[i+j*cn][8], weights[i+j*cn][8], 0, weights[i+j*cn][8], weights[i+j*cn][8], weights[i+j*cn][8], 0, weights[i+j*cn][8], weights[i+j*cn][8], weights[i+j*cn][8], 0, 0, 0, 0, 0});
        }
    }

    //    for (int i=0; i<co_cn; i++){
    //        cout << "weights: " << i << endl;
    //        for(int j=0; j<9; j++){
    //            cout << "j: " << weight_list[i][j] << endl;
    //        }
    //    }

    cc->EvalRotateKeyGen(keys.secretKey, {-5,-4,-3,-1,0,1,3,4,5,ih*iw});
    vector<int> rot_index = {-5,-4,-3,-1,0,1,3,4,5};
    vector<vector<vector<Ctxt>>> c_rotations(ci_cn, vector<vector<Ctxt>>(cn, vector<Ctxt>(9)));
    for (int i=0; i<ci_cn; i++){
        for (int j=0; j<cn; j++) {
            for (int k=0; k<9; k++) {
                c_rotations[i][j][k] = cc->EvalRotate(ct_inputs[i], rot_index[k]);
            }
            ct_inputs[i] = cc->EvalRotate(ct_inputs[i], ih * iw);
        }
    }

    //    for (int i=0; i<ci_cn; i++){
    //        for (int j=0; j<co; j++) {
    //            cout << "ct: " << i << ", " << j << endl;
    //            for (int k=0; k<9; k++) {
    //                Ptxt res;
    //                cc->Decrypt(keys.secretKey, c_rotations[i][j][k], &res);
    //                res->SetLength(numSlots);
    //                cout << "k: " << res;
    //            }
    //            cout << endl;
    //        }
    //    }

    vector<Ctxt> inter_out_ct(co_cn);
    for (int j = 0; j < co_cn; j++) {
        vector<Ctxt> inter_in_ct;
        for(int h=0; h < cn; h++){
            for(int l=0; l < ci_cn; l++) {
                vector<Ctxt> conv_ct;
                for (int k = 0; k < 9; k++) {
                    Ptxt weight_pt = cc->MakeCKKSPackedPlaintext(weight_list[j][k]);
                    Ctxt cMult     = cc->EvalMult(weight_pt, c_rotations[l][h][k]);
                    conv_ct.push_back(cMult);
                }
                Ctxt inter_conv_sum = cc->EvalAddMany(conv_ct);
                inter_in_ct.push_back(inter_conv_sum);
                //                Ptxt res;
                //                cc->Decrypt(keys.secretKey, inter_conv_sum, &res);
                //                res->SetLength(numSlots);
                //                cout << "inter: " << endl;
                //                cout << res << endl;
            }
        }
        Ctxt inter_out_sum = cc->EvalAddMany(inter_in_ct);
        inter_out_ct[j] = inter_out_sum;
    }

    for (int i=0; i<co_cn; i++){
        Ptxt res;
        cc->Decrypt(keys.secretKey, inter_out_ct[i], &res);
        res->SetLength(numSlots);
        cout << "out: " << i << endl;
        cout << res << endl;
    }

    return 0;
}
