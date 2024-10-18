//
// Created by Şeyda Nur Güzelhan on 10/2/24.
//
#include <iostream>
#include <vector>
#include <cmath>
#include "openfhe.h"
#include "enn/NN-utils.h"
#include "enn/utils.h"

using namespace std;
using namespace lbcrypto;

ENN ENN;

int main() {
    int numSlots = 8;
    int numChannels = 4;

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetRingDim((1 << 16));
    parameters.SetMultiplicativeDepth(2);
    parameters.SetFirstModSize(60);
    parameters.SetScalingModSize(55);

    int ni = 4;
    int no = 4;
    parameters.SetBatchSize(numSlots);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);

    vector<double> x1 = {0,2,3,0,2,3,4,5,3,0,0,2,6,1,0,1};

//    vector<vector<double>> weights(numChannels);
//    weights[0] = {1,2,1,0};
//    weights[1] = {-1,-2,-1,0};
//    weights[2] = {1,1,1,1};
//    weights[3] = {-1,-1,-1,-1};
    vector<double> weights = {1,2,1,0,-1,-2,-1,0,1,1,1,1,-1,-1,-1,-1};

    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalRotateKeyGen(keys.secretKey, {1,2,4,8,16,32,64});

    vector<Ctxt> c_rows(no);
    vector<Ptxt> w_rows(no);
    // Ruster-scan the image in steps of ni
    for (int i = 0; i < x1.size(); i += numSlots) {
        vector<double> row;
        vector<double> weight_row;

        if (i + numSlots <= x1.size()) {
            std::copy(x1.begin() + i, x1.begin() + i + numSlots, std::back_inserter(row));
            std::copy(weights.begin() + i, weights.begin() + i + numSlots, std::back_inserter(weight_row));
        } else {
            std::copy(x1.begin() + i, x1.end(), std::back_inserter(row));
            std::copy(weights.begin() + i, weights.end(), std::back_inserter(weight_row));
        }

        Ptxt pt_row = cc->MakeCKKSPackedPlaintext(row);
        c_rows[i/numSlots] = cc->Encrypt(keys.publicKey, pt_row);
        w_rows[i/numSlots] = cc->MakeCKKSPackedPlaintext(weight_row);
    }

    for (int j = 0; j < numChannels; j++) {
        vector<vector<Ctxt>> k_rows(numChannels);
        for (int k = 0; k < ceil((double)(no*ni)/numSlots); k++) {
            Ctxt cMult = cc->EvalMult(w_rows[k], c_rows[k]);

            auto cMult_new = cMult->Clone();
            for (int i=0; i<log2(ni); i++){
                cMult = cc->EvalAdd(cMult, cc->EvalRotate(cMult, pow(2, i)));
            }
            k_rows[j].push_back(cMult);

            Ptxt res;
            cc->Decrypt(keys.secretKey, k_rows[j][k], &res);
            res->SetLength(numSlots);
            cout << "Channel: " << j << ", Row: " << k << endl;
            cout << res << endl;
        }
    }
    return 0;
}
