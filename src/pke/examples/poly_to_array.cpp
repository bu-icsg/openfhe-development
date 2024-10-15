//
// Created by Şeyda Nur Güzelhan on 8/6/24.
//

#include <iostream>
#include <vector>
#include <chrono>
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

int main() {

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_NotSet);
    auto batchSize = 8;
    auto ringDim = 16;
    parameters.SetBatchSize(batchSize);
    parameters.SetMultiplicativeDepth(3);
    parameters.SetScalingModSize(50);
    parameters.SetFirstModSize(7);
    parameters.SetRingDim(ringDim);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);

    vector<double> x1 = {1, 2, 3, 4};

    auto keys= cc->KeyGen();
    Plaintext pt1 = cc->MakeCKKSPackedPlaintext(x1);

    Ciphertext<DCRTPoly> ct1 = cc->Encrypt(keys.publicKey, pt1);

//    vector<vector<vector<double>>> elems;
//    for(int i=0; i<2; i++){
//        DCRTPoly ct_poly = ct1->GetElements()[i];
//        for(int j=0; j<ct_poly.GetNumOfElements(); j++){
//            elems[i][j] = ct_poly.GetAllElements()[j];
//        }
//    }
    auto elems2 = ct1->GetElements()[0].GetAllElements()[0];

    int status;
    const char* mangled_name = typeid(elems2).name();
    char* demangled_name = abi::__cxa_demangle(mangled_name, nullptr, nullptr, &status);
    std::cout << "Type: " << (status == 0 ? demangled_name : mangled_name) << std::endl;
    free(demangled_name);

//    cout << "c0: " << endl;
//    cout << ct1 << endl << endl;
//
//    cout << "vector: " << endl;
//    for (int i=0; i<cc->GetRingDimension(); i++){
//        cout << elems2[i] << ", ";
//    }

    return 0;
}
