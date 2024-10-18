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
    int numSlots = 4;
    int numChannels = 4;

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
    vector<double> x1 = {0,2,3,6,   // diag
                              1,2,3,0,
                              0,0,3,4,
                              5,2,1,0};
    int ni = 4;
    int no = 4;

    vector<vector<double>> weights(numChannels);
    weights[0] = {1,2,1,0};
    weights[1] = {-1,-2,-1,0};
    weights[2] = {1,1,1,1};
    weights[3] = {-1,-1,-1,-1};


    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalRotateKeyGen(keys.secretKey, {0,1,2,3,4,8,16,32,64});

    vector<Ctxt> c_rows(no);

    // Ruster-scan the image in steps of ni
    for (int i = 0; i < x1.size(); i += ni) {
        vector<double> row;
        if (i + ni <= x1.size()) {
            std::copy(x1.begin() + i, x1.begin() + i + ni, std::back_inserter(row));
        } else {
            std::copy(x1.begin() + i, x1.end(), std::back_inserter(row));
        }

        Ptxt pt_row = cc->MakeCKKSPackedPlaintext(row);
        pt_row->SetLength(ni);
        c_rows[i/ni] = cc->Encrypt(keys.publicKey, pt_row);
    }

    for (int j = 0; j < numChannels; j++) {
        vector<Ctxt> k_rows;
        for (int k = 0; k < no; k++) {
            Ptxt weight_pt = cc->MakeCKKSPackedPlaintext(weights[j]);
            weight_pt->SetLength(4);
            Ctxt cMult = cc->EvalMult(weight_pt, c_rows[k]);
            cMult = cc->EvalRotate(cMult, k);
            k_rows.push_back(cMult);

        }
        Ctxt sum = cc->EvalAddMany(k_rows);
        Ptxt res;
        cc->Decrypt(keys.secretKey, sum, &res);
        res->SetLength(ni);
        cout << "Channel: " << j << endl;
        cout << res << endl;
    }
    return 0;
}
