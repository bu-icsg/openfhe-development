//
// Created by Şeyda Nur Güzelhan on 5/12/24.
//
#include <iostream>
#include <vector>
#include <chrono>
#include "openfhe.h"

using namespace std;
using namespace lbcrypto;

int main() {

    int batchsize = 8;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetBatchSize(batchsize); //!!!!!!!!!!!!!!!!!!!!!!!!

//    parameters.SetSecurityLevel(HEStd_NotSet);
//    parameters.SetRingDim(1 << 4);
//    parameters.SetScalingModSize(10);
//    parameters.SetFirstModSize(10);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(KEYSWITCH);


    vector<double> x1 = {1, 2, 3, 4, 1, 2, 3, 4};
    vector<double> x2 = {1, 2, 1, 2, 1, 2, 1, 2};

    auto keys= cc->KeyGen();
    cc->EvalRotateKeyGen(keys.secretKey, {1, -2});
    cc->EvalMultKeyGen(keys.secretKey);

    Plaintext pt1 = cc->MakeCKKSPackedPlaintext(x1);
    pt1->SetLength(batchsize);
    Plaintext pt2 = cc->MakeCKKSPackedPlaintext(x2);

    //    cout << "Plaintext (packed values): " << endl << pt1 << endl;
    //    cout << "Plaintext polynomial" << endl << pt1->GetElement<DCRTPoly>() << endl;

    //    cout << "Ciphertext Structure: c = (c0, c1)" << endl;
    //    cout << "c0, all limbs: " << endl;
    //    cout << ct1->GetElements()[0] << endl;
    //    cout << "c0, limb 0: " << endl;
    //    cout << ct1->GetElements()[0].GetAllElements()[0] << endl;
    //    cout << "c0, limb 1: " << endl;
    //    cout << ct1->GetElements()[0].GetAllElements()[1] << endl;
    //    ...
    //    cout << "c1, all limbs: " << endl;
    //    cout << ct2->GetElements()[1] << endl;


    auto ct1 = cc->Encrypt(keys.publicKey, pt1);
    auto ct2 = cc->Encrypt(keys.publicKey, pt2);


    // Homomorphic addition
    auto cAdd = cc->EvalAdd(ct1, ct2);

    // Homomorphic subtraction
    auto cSub = cc->EvalSub(ct1, ct2);

    // Homomorphic scalar multiplication
    auto cScalar = cc->EvalMult(ct1, 4.0);

    // Homomorphic multiplication
    auto cMul = cc->EvalMult(ct1, ct2);

    // Homomorphic rotations
    auto cRot1 = cc->EvalRotate(ct1, 1);
    auto cRot2 = cc->EvalRotate(ct1, -2);

    Plaintext pAdd, pMul, pSub, pScalar, pRot1, pRot2;

    cc->Decrypt(keys.secretKey, cAdd, &pAdd);
    pAdd->SetLength(batchsize);

    cc->Decrypt(keys.secretKey, cMul, &pMul);
    pMul->SetLength(batchsize);
    cc->Decrypt(keys.secretKey, cSub, &pSub);
    pSub->SetLength(batchsize);
    cc->Decrypt(keys.secretKey, cScalar, &pScalar);
    pScalar->SetLength(batchsize);
    cc->Decrypt(keys.secretKey, cRot1, &pRot1);
    pRot1->SetLength(batchsize);
    cc->Decrypt(keys.secretKey, cRot2, &pRot2);
    pRot2->SetLength(batchsize);

    cout << "Input Messages: " << endl;
    cout << "z1: " << x1 << endl;
    cout << "z2: " << x2 << endl;

    cout << "zAdd: "  << pAdd << endl;
    cout << "zMul: "  << pMul << endl;
    cout << "zSub: "  << pSub << endl;
    cout << "zScalar: "  << pScalar << endl;
    cout << "zRot1: "  << pRot1 << endl;
    cout << "zRot2: "  << pRot2 << endl;

//    cout << "ciphertext: "  << cAdd << endl;


    return 0;
}
