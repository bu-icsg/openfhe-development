//
// Created by Şeyda Nur Güzelhan on 10/11/24.
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
    int numSlots = (32);
    int numChannels = 2;

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
    vector<double> x1 = {0,2,3,0,2,3,4,5,3,0,0,2,6,1,0,1};
    vector<double> x2 = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
    vector<double> x12 = {0,2,3,0,2,3,4,5,3,0,0,2,6,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
    vector<vector<double>> weights(numChannels);
    weights[0] = {1,2,1,0,1,1,2,1,1,-1,-2,-1,0,-1,-1,-2,-1,-1};
    weights[1] = {-1,-2,-1,0,-1,-1,-2,-1,-1,1,2,1,0,1,1,2,1,1};

    Ptxt pt1 = cc->MakeCKKSPackedPlaintext(x12);
    pt1->SetLength(numSlots);

    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);

    Ctxt ct1 = cc->Encrypt(keys.publicKey, pt1);

    vector<vector<vector<double>>> weight_list{9};
    for(int i=0; i < 2; i++) {
        numSlots = 18;
        weight_list[i].push_back({0, 0, 0, 0, 0, weights[i][0], weights[i][0], weights[i][0], 0, weights[i][0], weights[i][0], weights[i][0], 0, weights[i][0], weights[i][0], weights[i][0], 0, 0, 0, 0, 0, weights[i][0+numSlots/2], weights[i][0+numSlots/2], weights[i][0+numSlots/2], 0, weights[i][0+numSlots/2], weights[i][0+numSlots/2], weights[i][0+numSlots/2], 0, weights[i][0+numSlots/2], weights[i][0+numSlots/2], weights[i][0+numSlots/2]});
        weight_list[i].push_back({0, 0, 0, 0, weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1], weights[i][1],0, 0, 0, 0, weights[i][1+numSlots/2], weights[i][1+numSlots/2], weights[i][1+numSlots/2], weights[i][1+numSlots/2], weights[i][1+numSlots/2], weights[i][1+numSlots/2], weights[i][1+numSlots/2], weights[i][1+numSlots/2], weights[i][1+numSlots/2], weights[i][1+numSlots/2], weights[i][1+numSlots/2], weights[i][1+numSlots/2]});
        weight_list[i].push_back({0, 0, 0, 0, weights[i][2], weights[i][2], weights[i][2], 0, weights[i][2], weights[i][2], weights[i][2], 0, weights[i][2], weights[i][2], weights[i][2], 0, 0, 0, 0, 0, weights[i][2+numSlots/2], weights[i][2+numSlots/2], weights[i][2+numSlots/2], 0, weights[i][2+numSlots/2], weights[i][2+numSlots/2], weights[i][2+numSlots/2], 0, weights[i][2+numSlots/2], weights[i][2+numSlots/2], weights[i][2+numSlots/2], 0});
        weight_list[i].push_back({0, weights[i][3], weights[i][3], weights[i][3], 0, weights[i][3], weights[i][3], weights[i][3], 0, weights[i][3], weights[i][3], weights[i][3], 0, weights[i][3], weights[i][3], weights[i][3], 0, weights[i][3+numSlots/2], weights[i][3+numSlots/2], weights[i][3+numSlots/2], 0, weights[i][3+numSlots/2], weights[i][3+numSlots/2], weights[i][3+numSlots/2], 0, weights[i][3+numSlots/2], weights[i][3+numSlots/2], weights[i][3+numSlots/2], 0, weights[i][3+numSlots/2], weights[i][3+numSlots/2], weights[i][3+numSlots/2]});
        weight_list[i].push_back({weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4], weights[i][4+numSlots/2], weights[i][4+numSlots/2], weights[i][4+numSlots/2], weights[i][4+numSlots/2], weights[i][4+numSlots/2], weights[i][4+numSlots/2], weights[i][4+numSlots/2], weights[i][4+numSlots/2], weights[i][4+numSlots/2], weights[i][4+numSlots/2], weights[i][4+numSlots/2], weights[i][4+numSlots/2], weights[i][4+numSlots/2], weights[i][4+numSlots/2], weights[i][4+numSlots/2], weights[i][4+numSlots/2]});
        weight_list[i].push_back({weights[i][5], weights[i][5], weights[i][5], 0, weights[i][5], weights[i][5], weights[i][5], 0, weights[i][5], weights[i][5], weights[i][5], 0, weights[i][5], weights[i][5], weights[i][5], 0, weights[i][5+numSlots/2], weights[i][5+numSlots/2], weights[i][5+numSlots/2], 0, weights[i][5+numSlots/2], weights[i][5+numSlots/2], weights[i][5+numSlots/2], 0, weights[i][5+numSlots/2], weights[i][5+numSlots/2], weights[i][5+numSlots/2], 0, weights[i][5+numSlots/2], weights[i][5+numSlots/2], weights[i][5+numSlots/2], 0});
        weight_list[i].push_back({0, weights[i][6], weights[i][6], weights[i][6], 0, weights[i][6], weights[i][6], weights[i][6], 0, weights[i][6], weights[i][6], weights[i][6], 0, 0, 0, 0, 0, weights[i][6+numSlots/2], weights[i][6+numSlots/2], weights[i][6+numSlots/2], 0, weights[i][6+numSlots/2], weights[i][6+numSlots/2], weights[i][6+numSlots/2], 0, weights[i][6+numSlots/2], weights[i][6+numSlots/2], weights[i][6+numSlots/2], 0, 0, 0, 0});
        weight_list[i].push_back({weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], weights[i][7], 0, 0, 0, 0, weights[i][7+numSlots/2], weights[i][7+numSlots/2], weights[i][7+numSlots/2], weights[i][7+numSlots/2], weights[i][7+numSlots/2], weights[i][7+numSlots/2], weights[i][7+numSlots/2], weights[i][7+numSlots/2], weights[i][7+numSlots/2], weights[i][7+numSlots/2], weights[i][7+numSlots/2], weights[i][7+numSlots/2], 0, 0, 0, 0});
        weight_list[i].push_back({weights[i][8], weights[i][8], weights[i][8], 0, weights[i][8], weights[i][8], weights[i][8], 0, weights[i][8], weights[i][8], weights[i][8], 0, 0, 0, 0, 0, weights[i][8+numSlots/2], weights[i][8+numSlots/2], weights[i][8+numSlots/2], 0, weights[i][8+numSlots/2], weights[i][8+numSlots/2], weights[i][8+numSlots/2], 0, weights[i][8+numSlots/2], weights[i][8+numSlots/2], weights[i][8+numSlots/2], 0, 0, 0, 0, 0});
    }
    numSlots = 32;
    vector<vector<Ctxt>> c_rotations{9};

    cc->EvalRotateKeyGen(keys.secretKey, {-5,-4,-3,-1,1,3,4,5,numSlots/2});

    cout << fixed;
    cout << setprecision(0);

    c_rotations[0].push_back(cc->EvalRotate(ct1, -5));
    c_rotations[0].push_back(cc->EvalRotate(ct1, -4));
    c_rotations[0].push_back(cc->EvalRotate(ct1, -3));
    c_rotations[0].push_back(cc->EvalRotate(ct1, -1));
    c_rotations[0].push_back(ct1);
    c_rotations[0].push_back(cc->EvalRotate(ct1, 1));
    c_rotations[0].push_back(cc->EvalRotate(ct1, 3));
    c_rotations[0].push_back(cc->EvalRotate(ct1, 4));
    c_rotations[0].push_back(cc->EvalRotate(ct1, 5));

    Ctxt ctRot = cc->EvalRotate(ct1, numSlots/2);
    c_rotations[1].push_back(cc->EvalRotate(ctRot, -5));
    c_rotations[1].push_back(cc->EvalRotate(ctRot, -4));
    c_rotations[1].push_back(cc->EvalRotate(ctRot, -3));
    c_rotations[1].push_back(cc->EvalRotate(ctRot, -1));
    c_rotations[1].push_back(ctRot);
    c_rotations[1].push_back(cc->EvalRotate(ctRot, 1));
    c_rotations[1].push_back(cc->EvalRotate(ctRot, 3));
    c_rotations[1].push_back(cc->EvalRotate(ctRot, 4));
    c_rotations[1].push_back(cc->EvalRotate(ctRot, 5));

    vector<Ctxt> j_channels;
    for (int j = 0; j < numChannels; j++) {
        vector<Ctxt> k_rows;

        for (int k = 0; k < 9; k++) {
            Ptxt weight_pt = cc->MakeCKKSPackedPlaintext(weight_list[0][k]);
            Ctxt cMult = cc->EvalMult(weight_pt, c_rotations[j][k]);
            k_rows.push_back(cMult);
        }
        Ctxt sum = cc->EvalAddMany(k_rows);
        j_channels.push_back(sum);

//        Ptxt res;
//        cc->Decrypt(keys.secretKey, sum, &res);
//        res->SetLength(numSlots);
//        cout << "intermediate ciphertext: " << j << endl;
//        cout << res << endl;
    }
    Ctxt sum = cc->EvalAddMany(j_channels);
    Ptxt res;
    cc->Decrypt(keys.secretKey, sum, &res);
    res->SetLength(numSlots);
    cout << "Convolution result: " << endl;
    cout << res << endl;

    return 0;
}
